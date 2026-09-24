/* SPDX-License-Identifier: GPL-2.0-only */
/* Raw syscall tests: do not let libc emulate epoll_pwait2 on old kernels. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

struct kernel_timespec { int64_t tv_sec, tv_nsec; };
static int failures;
static volatile sig_atomic_t handled;

static void check(int ok, const char *name)
{
	printf("%s [%zu-bit] %s\n", ok ? "PASS" : "FAIL", sizeof(void *) * 8, name);
	if (!ok)
		failures++;
}

static long pwait2(int fd, struct epoll_event *events, int count,
		   const struct kernel_timespec *timeout, const uint64_t *mask,
		   size_t size)
{
	return syscall(441, fd, events, count, timeout, mask, size);
}

static int64_t monotonic_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		abort();
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void handler(int sig) { handled = sig; }

static int suite(void)
{
	struct kernel_timespec zero = {0}, tiny = {0, 1}, delay = {0, 20000000};
	struct kernel_timespec bad_sec = {-1, 0}, bad_nsec = {0, 1000000000};
	struct kernel_timespec negative_nsec = {0, -1}, huge = {INT64_MAX, 0};
	struct epoll_event event = {0};
	int epfd = epoll_create1(0), fd;
	uint64_t original = 0, after = 0, empty = 0;
	/* Include a high-word signal to exercise AArch32 compat sigset layout. */
	uint64_t mask = (1ULL << (SIGUSR1 - 1)) | (1ULL << (SIGRTMIN - 1));

	check(epfd >= 0, "epoll_create1");
	if (epfd < 0)
		return 1;
	check(pwait2(epfd, &event, 1, &zero, NULL, 8) == 0, "zero timeout");
	check(pwait2(epfd, &event, 1, &tiny, NULL, 8) == 0, "one-nanosecond timeout terminates");
	int64_t start = monotonic_ns();
	check(pwait2(epfd, &event, 1, &delay, NULL, 8) == 0, "finite timeout");
	check(monotonic_ns() - start >= 20000000, "finite timeout does not return early");
	check(pwait2(epfd, &event, 1, &bad_sec, NULL, 8) == -1 && errno == EINVAL,
	      "negative seconds rejected");
	check(pwait2(epfd, &event, 1, &bad_nsec, NULL, 8) == -1 && errno == EINVAL,
	      "nanoseconds >= 1e9 rejected");
	check(pwait2(epfd, &event, 1, &negative_nsec, NULL, 8) == -1 && errno == EINVAL,
	      "negative nanoseconds rejected");
	check(pwait2(epfd, &event, 1, (void *)1, NULL, 8) == -1 && errno == EFAULT,
	      "bad timeout pointer rejected");
	check(pwait2(-1, &event, 1, &zero, NULL, 8) == -1 && errno == EBADF,
	      "bad epoll fd rejected");
	check(pwait2(epfd, &event, 0, &zero, NULL, 8) == -1 && errno == EINVAL,
	      "zero maxevents rejected");
	check(pwait2(epfd, &event, 1, &zero, &mask, 4) == -1 && errno == EINVAL,
	      "bad sigset size rejected");
	check(pwait2(epfd, &event, 1, &zero, (void *)1, 8) == -1 && errno == EFAULT,
	      "bad sigset pointer rejected");
	check(syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &original, 8) == 0,
	      "read original mask");
	check(pwait2(epfd, &event, 1, &zero, &mask, 8) == 0, "temporary signal mask");
	check(syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &after, 8) == 0 && after == original,
	      "mask restored after timeout");
	check(pwait2(-1, &event, 1, &zero, &mask, 8) == -1 && errno == EBADF,
	      "error under temporary signal mask");
	check(syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &after, 8) == 0 && after == original,
	      "mask restored after error");

	struct sigaction action = {.sa_handler = handler};
	sigemptyset(&action.sa_mask);
	check(sigaction(SIGUSR1, &action, NULL) == 0, "install signal handler");
	check(syscall(SYS_rt_sigprocmask, SIG_BLOCK, &mask, NULL, 8) == 0, "block test signal");
	check(kill(getpid(), SIGUSR1) == 0, "queue blocked signal");
	check(pwait2(epfd, &event, 1, NULL, &empty, 8) == -1 && errno == EINTR,
	      "atomic signal unblock interrupts infinite wait");
	check(handled == SIGUSR1, "signal handler executed");
	check(syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &after, 8) == 0 &&
	      after == (original | mask), "mask restored after EINTR");
	check(syscall(SYS_rt_sigprocmask, SIG_SETMASK, &original, NULL, 8) == 0,
	      "restore original test mask");

	check(syscall(SYS_epoll_pwait, epfd, &event, 1, 0, NULL, 8) == 0,
	      "legacy epoll_pwait zero timeout");
	start = monotonic_ns();
	check(syscall(SYS_epoll_pwait, epfd, &event, 1, 20, &mask, 8) == 0 &&
	      monotonic_ns() - start >= 20000000, "legacy millisecond timeout");
	check(syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &after, 8) == 0 && after == original,
	      "legacy mask restored");

	fd = eventfd(1, EFD_NONBLOCK);
	event.events = EPOLLIN;
	event.data.u64 = 0x123456789abcdef0ULL;
	check(fd >= 0 && epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event) == 0, "register ready eventfd");
	check(pwait2(epfd, &event, 1, NULL, NULL, 8) == 1 &&
	      event.data.u64 == 0x123456789abcdef0ULL, "NULL timeout delivers ready event");
	check(pwait2(epfd, &event, 1, &huge, NULL, 8) == 1, "huge timeout with ready event");
	check(pwait2(epfd, (void *)1, 1, &zero, NULL, 8) == -1 && errno == EFAULT,
	      "bad ready-event output pointer rejected");
	check(syscall(SYS_epoll_pwait, epfd, &event, 1, -1, NULL, 8) == 1,
	      "legacy infinite timeout delivers ready event");
	close(fd);
	close(epfd);
	return failures ? 1 : 0;
}

int main(void)
{
	int is_init = getpid() == 1;
	if (is_init) {
		mkdir("/dev", 0755);
		mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
		int console = open("/dev/console", O_RDWR);
		if (console >= 0) {
			dup2(console, 0); dup2(console, 1); dup2(console, 2);
			if (console > 2) close(console);
		}
	}
	setbuf(stdout, NULL);
	int result = suite();
	if (!is_init)
		return result;
	pid_t child = fork();
	if (child == 0) {
		execl("/test32", "test32", NULL);
		perror("exec test32");
		_exit(127);
	}
	int status = 0;
	if (child < 0 || waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		result = 1;
	puts(result ? "EPOLL_PWAIT2_TESTS_FAILED" : "EPOLL_PWAIT2_TESTS_PASSED");
	sync();
	reboot(RB_POWER_OFF);
	for (;;) pause();
}
