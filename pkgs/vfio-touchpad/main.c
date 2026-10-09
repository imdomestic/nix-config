#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <libevdev/libevdev-uinput.h>
#include <libinput.h>
#include <linux/input.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int signum) { (void)signum; stopping = 1; }

static int open_input(const char *path, int flags, void *data) {
    (void)data;
    int fd = open(path, flags | O_CLOEXEC);
    if (fd < 0) return -errno;
    if (ioctl(fd, EVIOCGRAB, 1) < 0) {
        int error = errno;
        close(fd);
        return -error;
    }
    return fd;
}
static void close_input(int fd, void *data) { (void)data; close(fd); }
static const struct libinput_interface interface = {
    .open_restricted = open_input, .close_restricted = close_input,
};

static void emit(struct libevdev_uinput *out, unsigned type, unsigned code, int value) {
    int rc = libevdev_uinput_write_event(out, type, code, value);
    if (rc < 0) {
        fprintf(stderr, "Writing virtual pointer failed: %s\n", strerror(-rc));
        exit(EXIT_FAILURE);
    }
}

/* Preserve subpixel movement and reset scroll remainders at finger lift. */
static void relative(struct libevdev_uinput *out, unsigned code, double value,
                     double *remainder) {
    *remainder += value;
    int whole = (int)*remainder;
    *remainder -= whole;
    if (whole) emit(out, EV_REL, code, whole);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: vfio-touchpad /dev/input/<touchpad>\n");
        return EXIT_FAILURE;
    }
    struct sigaction action = {.sa_handler = stop};
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    struct libinput *li = libinput_path_create_context(&interface, NULL);
    if (!li) return EXIT_FAILURE;
    struct libinput_device *pad = libinput_path_add_device(li, argv[1]);
    if (!pad || libinput_device_config_tap_get_finger_count(pad) == 0) {
        fprintf(stderr, "Cannot open a supported touchpad: %s\n", argv[1]);
        libinput_unref(li);
        return EXIT_FAILURE;
    }
    libinput_device_config_tap_set_enabled(pad, LIBINPUT_CONFIG_TAP_ENABLED);
    libinput_device_config_tap_set_drag_enabled(pad, LIBINPUT_CONFIG_DRAG_ENABLED);
    libinput_device_config_scroll_set_method(pad, LIBINPUT_CONFIG_SCROLL_2FG);
    libinput_device_config_click_set_method(pad, LIBINPUT_CONFIG_CLICK_METHOD_CLICKFINGER);

    struct libevdev *dev = libevdev_new();
    if (!dev) { libinput_unref(li); return EXIT_FAILURE; }
    libevdev_set_name(dev, "VFIO relative touchpad");
    libevdev_set_id_bustype(dev, BUS_VIRTUAL);
    const unsigned axes[] = {REL_X, REL_Y, REL_WHEEL, REL_HWHEEL};
    const unsigned buttons[] = {BTN_LEFT, BTN_RIGHT, BTN_MIDDLE};
    int rc = 0;
    for (unsigned i = 0; i < sizeof(axes) / sizeof(*axes); i++)
        rc |= libevdev_enable_event_code(dev, EV_REL, axes[i], NULL);
    for (unsigned i = 0; i < sizeof(buttons) / sizeof(*buttons); i++)
        rc |= libevdev_enable_event_code(dev, EV_KEY, buttons[i], NULL);
    struct libevdev_uinput *out = NULL;
    if (!rc) rc = libevdev_uinput_create_from_device(dev, LIBEVDEV_UINPUT_OPEN_MANAGED, &out);
    libevdev_free(dev);
    if (rc < 0) {
        fprintf(stderr, "Creating virtual pointer failed: %s\n", strerror(-rc));
        libinput_unref(li);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Relative pointer ready: %s\n", libevdev_uinput_get_devnode(out));
    double dx = 0, dy = 0, scroll_x = 0, scroll_y = 0;
    struct pollfd pfd = {.fd = libinput_get_fd(li), .events = POLLIN};
    bool removed = false;
    while (!stopping && !removed) {
        rc = libinput_dispatch(li);
        if (rc < 0) break;
        struct libinput_event *event;
        while ((event = libinput_get_event(li))) {
            enum libinput_event_type type = libinput_event_get_type(event);
            if (type == LIBINPUT_EVENT_DEVICE_REMOVED) removed = true;
            if (type == LIBINPUT_EVENT_POINTER_MOTION ||
                type == LIBINPUT_EVENT_POINTER_BUTTON ||
                type == LIBINPUT_EVENT_POINTER_SCROLL_FINGER) {
                struct libinput_event_pointer *pointer = libinput_event_get_pointer_event(event);
                if (type == LIBINPUT_EVENT_POINTER_MOTION) {
                    relative(out, REL_X, libinput_event_pointer_get_dx(pointer), &dx);
                    relative(out, REL_Y, libinput_event_pointer_get_dy(pointer), &dy);
                } else if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
                    unsigned button = libinput_event_pointer_get_button(pointer);
                    if (button >= BTN_LEFT && button <= BTN_MIDDLE)
                        emit(out, EV_KEY, button, libinput_event_pointer_get_button_state(pointer)
                             == LIBINPUT_BUTTON_STATE_PRESSED);
                } else {
                    for (int horizontal = 0; horizontal < 2; horizontal++) {
                        enum libinput_pointer_axis axis = horizontal
                            ? LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL
                            : LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL;
                        if (!libinput_event_pointer_has_axis(pointer, axis)) continue;
                        double value = libinput_event_pointer_get_scroll_value(pointer, axis);
                        double *remainder = horizontal ? &scroll_x : &scroll_y;
                        if (value == 0) *remainder = 0;
                        else relative(out, horizontal ? REL_HWHEEL : REL_WHEEL,
                                      value * (horizontal ? 1 : -1) / 15.0, remainder);
                    }
                }
                emit(out, EV_SYN, SYN_REPORT, 0);
            }
            libinput_event_destroy(event);
        }
        if (removed || stopping) break;
        rc = poll(&pfd, 1, 1000);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0 || (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) { rc = -1; break; }
    }
    libevdev_uinput_destroy(out);
    libinput_unref(li);
    return (removed || (rc < 0 && !stopping)) ? EXIT_FAILURE : EXIT_SUCCESS;
}
