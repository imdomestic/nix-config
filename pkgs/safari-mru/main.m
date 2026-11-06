#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Carbon/Carbon.h>
#import "history.h"

static id attribute(id element, CFStringRef name) {
    CFTypeRef value = NULL;
    if (AXUIElementCopyAttributeValue((__bridge AXUIElementRef)element, name, &value) != kAXErrorSuccess) return nil;
    return CFBridgingRelease(value);
}

static void collectTabs(id element, NSMutableArray *tabs, NSUInteger depth) {
    if (depth > 12) return;
    NSString *role = attribute(element, kAXRoleAttribute);
    if ([attribute(element, kAXSubroleAttribute) isEqual:@"AXTabButton"]) {
        [tabs addObject:element];
        return;
    }
    // Never walk page content, menus, or the sidebar's unrelated controls.
    if ([@[@"AXWebArea", @"AXScrollArea", @"AXMenuBar", @"AXOutline"] containsObject:role]) return;
    for (id child in attribute(element, kAXChildrenAttribute)) collectTabs(child, tabs, depth + 1);
}

static NSArray *tabsInWindow(id window) {
    NSMutableArray *tabs = [NSMutableArray array];
    collectTabs(window, tabs, 0);
    return tabs;
}

static id selectedTab(NSArray *tabs) {
    for (id tab in tabs) if ([attribute(tab, kAXValueAttribute) boolValue]) return tab;
    return nil;
}

@interface SafariMRU : NSObject
@property(nonatomic, strong) id application;
@property(nonatomic, strong) id window;
@property(nonatomic, strong) NSMapTable *histories;
@property(nonatomic, strong) MRUHistory *history;
@property(nonatomic, copy) NSArray *tabs;
@property(nonatomic) pid_t pid;
@property(nonatomic) EventHotKeyRef forwardKey;
@property(nonatomic) EventHotKeyRef backwardKey;
@property(nonatomic) EventHotKeyRef cancelKey;
@property(nonatomic) EventHotKeyRef cancelShiftKey;
@property(nonatomic) EventHandlerRef handler;
@property(nonatomic) AXObserverRef observer;
@property(nonatomic, copy) NSArray *tabContainers;
@property(nonatomic, copy) NSArray *sheets;
@property(nonatomic, strong) id modifierMonitor;
@property(nonatomic) BOOL reportedMissingPermission;
@property(nonatomic) BOOL synchronizationQueued;
@property(nonatomic) BOOL sessionInactive;
@property(nonatomic) NSTimeInterval lastControlRelease;
@property(nonatomic) EventTime gestureStarted;
@property(nonatomic, strong) dispatch_source_t statusSignal;
@property(nonatomic) NSUInteger keyPresses;
@property(nonatomic) NSUInteger selectionEvents;
@property(nonatomic) NSUInteger activationRequests;
@property(nonatomic) NSUInteger activationErrors;
- (void)refresh;
- (void)synchronize;
- (void)accessibilityChanged:(id)element notification:(NSString *)notification;
- (void)switchBackward:(BOOL)backward timestamp:(EventTime)timestamp;
- (void)commitGesture;
- (void)cancelGesture;
- (void)logStatus;
@end

static OSStatus hotKeyHandler(EventHandlerCallRef next, EventRef event, void *context) {
    (void)next;
    EventHotKeyID key = {0};
    OSStatus status = GetEventParameter(event, kEventParamDirectObject, typeEventHotKeyID,
                                       NULL, sizeof(key), NULL, &key);
    if (status == noErr) {
        SafariMRU *controller = (__bridge SafariMRU *)context;
        if (key.id == 3 || key.id == 4) [controller cancelGesture];
        else [controller switchBackward:key.id == 2 timestamp:GetEventTime(event)];
    }
    return status;
}

static void accessibilityChanged(AXObserverRef observer, AXUIElementRef element,
                                  CFStringRef notification, void *context) {
    (void)observer;
    [(__bridge SafariMRU *)context accessibilityChanged:(__bridge id)element
                                          notification:(__bridge NSString *)notification];
}

@implementation SafariMRU
- (instancetype)init {
    if ((self = [super init])) {
        _histories = [NSMapTable strongToStrongObjectsMapTable];
        EventTypeSpec type = {kEventClassKeyboard, kEventHotKeyPressed};
        OSStatus status = InstallEventHandler(GetApplicationEventTarget(), hotKeyHandler,
                                             1, &type, (__bridge void *)self, &_handler);
        if (status != noErr) {
            NSLog(@"Cannot install hotkey handler (%d)", (int)status);
            exit(1);
        }
    }
    return self;
}

- (void)unregisterKeys {
    if (_forwardKey) UnregisterEventHotKey(_forwardKey);
    if (_backwardKey) UnregisterEventHotKey(_backwardKey);
    _forwardKey = NULL;
    _backwardKey = NULL;
    [self cancelGesture];
}

- (void)unregisterCancelKeys {
    if (_cancelKey) UnregisterEventHotKey(_cancelKey);
    if (_cancelShiftKey) UnregisterEventHotKey(_cancelShiftKey);
    _cancelKey = NULL;
    _cancelShiftKey = NULL;
}

- (void)registerCancelKeys {
    if (_cancelKey) return;
    EventHotKeyID key = {.signature = 'SMRU', .id = 3};
    OSStatus status = RegisterEventHotKey(kVK_Escape, controlKey, key, GetApplicationEventTarget(),
                                         kEventHotKeyExclusive, &_cancelKey);
    if (status == noErr) {
        key.id = 4;
        status = RegisterEventHotKey(kVK_Escape, controlKey | shiftKey, key, GetApplicationEventTarget(),
                                     kEventHotKeyExclusive, &_cancelShiftKey);
    }
    if (status != noErr) {
        [self unregisterCancelKeys];
        NSLog(@"Cannot register Escape to cancel (%d)", (int)status);
    }
}

- (void)cancelGesture {
    [self.history cancel];
    self.gestureStarted = 0;
    [self unregisterCancelKeys];
}

- (void)logStatus {
    NSLog(@"status: version=%@ bundle=%@ permission=%s safariFront=%s tabs=%lu hotkeys=%s gesture=%s keyPresses=%lu selectionEvents=%lu activationRequests=%lu activationErrors=%lu",
          [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"], NSBundle.mainBundle.bundleIdentifier,
          AXIsProcessTrusted() ? "yes" : "no",
          [NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqual:@"com.apple.Safari"] ? "yes" : "no",
          (unsigned long)self.tabs.count, _forwardKey && _backwardKey ? "yes" : "no",
          self.history.cycle ? "yes" : "no", (unsigned long)self.keyPresses,
          (unsigned long)self.selectionEvents, (unsigned long)self.activationRequests, (unsigned long)self.activationErrors);
}

- (void)registerKeys {
    if (_forwardKey) return;
    EventHotKeyID key = {.signature = 'SMRU', .id = 1};
    OSStatus status = RegisterEventHotKey(kVK_Tab, controlKey, key, GetApplicationEventTarget(),
                                         kEventHotKeyExclusive, &_forwardKey);
    if (status == noErr) {
        key.id = 2;
        status = RegisterEventHotKey(kVK_Tab, controlKey | shiftKey, key, GetApplicationEventTarget(),
                                     kEventHotKeyExclusive, &_backwardKey);
    }
    if (status != noErr) {
        [self unregisterKeys];
        NSLog(@"Cannot register Ctrl+Tab (%d); another shortcut utility may own it", (int)status);
        exit(1);
    }
    NSLog(@"Safari MRU ready: %lu tabs; Ctrl+Tab registered", (unsigned long)self.tabs.count);
}

- (void)resetApplication {
    [self unregisterKeys];
    if (self.modifierMonitor) {
        [NSEvent removeMonitor:self.modifierMonitor];
        self.modifierMonitor = nil;
    }
    if (_observer) {
        CFRunLoopRemoveSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(_observer), kCFRunLoopCommonModes);
        CFRelease(_observer);
        _observer = NULL;
    }
    [self.histories removeAllObjects];
    self.history = nil;
    self.window = nil;
    self.application = nil;
    self.tabs = @[];
    self.tabContainers = @[];
    self.sheets = @[];
    self.pid = 0;
}

- (void)queueSynchronization {
    if (self.synchronizationQueued) return;
    self.synchronizationQueued = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        self.synchronizationQueued = NO;
        [self synchronize];
    });
}

- (void)accessibilityChanged:(id)element notification:(NSString *)notification {
    if (self.sessionInactive || ![NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqual:@"com.apple.Safari"]) return;
    if ([notification isEqual:(__bridge NSString *)kAXValueChangedNotification]) {
        if (![attribute(element, kAXSubroleAttribute) isEqual:@"AXTabButton"] ||
            ![attribute(element, kAXValueAttribute) boolValue]) return;
        self.selectionEvents++;
        if ([self.tabs containsObject:element]) {
            [self.history observeTabs:self.tabs selected:element];
            if (!self.history.cycle) [self unregisterCancelKeys];
        } else {
            [self queueSynchronization];
        }
        return;
    }
    if ([notification isEqual:(__bridge NSString *)kAXUIElementDestroyedNotification]) {
        // Destroyed AX elements may only be compared, never queried.
        if ([element isEqual:self.window] || [self.tabs containsObject:element] ||
            [self.tabContainers containsObject:element] || [self.sheets containsObject:element]) {
            [self queueSynchronization];
        }
        return;
    }
    if ([notification isEqual:(__bridge NSString *)kAXCreatedNotification]) {
        NSString *role = attribute(element, kAXRoleAttribute);
        if (![attribute(element, kAXSubroleAttribute) isEqual:@"AXTabButton"] &&
            ![@[@"AXWindow", @"AXSheet"] containsObject:role]) return;
    } else if ([notification isEqual:(__bridge NSString *)kAXSelectedChildrenChangedNotification]) {
        if (![element isEqual:self.window] && ![self.tabContainers containsObject:element]) return;
    }
    [self queueSynchronization];
}

- (void)synchronize {
    if (!self.application) return;
    if (self.sessionInactive || ![NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqual:@"com.apple.Safari"]) {
        [self unregisterKeys];
        return;
    }
    id window = attribute(self.application, kAXFocusedWindowAttribute);
    if (![window isEqual:self.window]) {
        [self cancelGesture];
        self.window = window;
        self.history = window ? [self.histories objectForKey:window] : nil;
        if (window && !self.history) {
            self.history = [[MRUHistory alloc] init];
            [self.histories setObject:self.history forKey:window];
        }
    }
    NSMutableArray *sheets = [NSMutableArray array];
    for (id child in attribute(window, kAXChildrenAttribute)) {
        if ([attribute(child, kAXRoleAttribute) isEqual:@"AXSheet"]) [sheets addObject:child];
    }
    self.sheets = sheets;
    self.tabs = window && !sheets.count ? tabsInWindow(window) : @[];
    NSMutableArray *containers = [NSMutableArray array];
    for (id tab in self.tabs) {
        id parent = attribute(tab, kAXParentAttribute);
        if (parent && ![containers containsObject:parent]) [containers addObject:parent];
    }
    self.tabContainers = containers;
    id selected = selectedTab(self.tabs);
    if (selected) [self.history observeTabs:self.tabs selected:selected];
    if (!self.history.cycle) [self unregisterCancelKeys];
    NSArray *windows = attribute(self.application, kAXWindowsAttribute);
    if (windows) for (id key in self.histories.keyEnumerator.allObjects) {
        if (![windows containsObject:key]) [self.histories removeObjectForKey:key];
    }
    // A hidden tab bar or a sheet must leave Safari's normal shortcut available.
    if (self.tabs.count >= 2 && selected) [self registerKeys];
    else [self unregisterKeys];
}

- (void)refresh {
    NSRunningApplication *front = NSWorkspace.sharedWorkspace.frontmostApplication;
    if (!AXIsProcessTrusted()) {
        if (self.application) [self resetApplication];
        if (!AXIsProcessTrusted() && !self.reportedMissingPermission) {
            NSLog(@"Waiting for Accessibility permission for Safari MRU; see docs/safari-mru.md");
            self.reportedMissingPermission = YES;
        }
        return;
    }
    if (self.reportedMissingPermission) {
        NSLog(@"Accessibility permission granted");
        self.reportedMissingPermission = NO;
    }
    if (self.sessionInactive || ![front.bundleIdentifier isEqual:@"com.apple.Safari"]) {
        [self unregisterKeys];
        if (self.modifierMonitor) {
            [NSEvent removeMonitor:self.modifierMonitor];
            self.modifierMonitor = nil;
        }
        NSRunningApplication *safari = [NSRunningApplication runningApplicationWithProcessIdentifier:self.pid];
        if (self.pid && (!safari || safari.terminated)) [self resetApplication];
        return;
    }
    if (front.processIdentifier != self.pid) {
        [self resetApplication];
        self.pid = front.processIdentifier;
        self.application = CFBridgingRelease(AXUIElementCreateApplication(self.pid));
        AXUIElementSetMessagingTimeout((__bridge AXUIElementRef)self.application, 0.15);
        if (AXObserverCreate(self.pid, accessibilityChanged, &_observer) == kAXErrorSuccess) {
            CFRunLoopAddSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(_observer), kCFRunLoopCommonModes);
            // App-level subscriptions also receive events from tabs created later.
            NSArray *notifications = @[
                (__bridge NSString *)kAXValueChangedNotification,
                (__bridge NSString *)kAXFocusedWindowChangedNotification,
                (__bridge NSString *)kAXWindowCreatedNotification,
                (__bridge NSString *)kAXCreatedNotification,
                (__bridge NSString *)kAXUIElementDestroyedNotification,
                (__bridge NSString *)kAXSelectedChildrenChangedNotification,
                (__bridge NSString *)kAXSheetCreatedNotification,
            ];
            for (NSString *notification in notifications) {
                AXError error = AXObserverAddNotification(_observer, (__bridge AXUIElementRef)self.application,
                                                          (__bridge CFStringRef)notification, (__bridge void *)self);
                if (error != kAXErrorSuccess) NSLog(@"Cannot observe %@ (%d)", notification, error);
            }
        } else {
            NSLog(@"Cannot observe Safari Accessibility events");
            exit(1);
        }
    }
    if (!self.modifierMonitor) {
        self.modifierMonitor = [NSEvent addGlobalMonitorForEventsMatchingMask:NSEventMaskFlagsChanged
            handler:^(NSEvent *event) {
                if (!(event.modifierFlags & NSEventModifierFlagControl)) {
                    self.lastControlRelease = MAX(self.lastControlRelease, event.timestamp);
                    if (event.timestamp >= self.gestureStarted) [self commitGesture];
                }
            }];
    }
    [self synchronize];
}

- (void)commitGesture {
    if (!self.history.cycle) return;
    if (self.sessionInactive || ![NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqual:@"com.apple.Safari"]) {
        [self cancelGesture];
        return;
    }
    [self synchronize];
    id target = [self.history commit];
    self.gestureStarted = 0;
    [self unregisterCancelKeys];
    if (!target || [target isEqual:self.history.selected]) return;
    self.activationRequests++;
    AXError error = AXUIElementPerformAction((__bridge AXUIElementRef)target, kAXPressAction);
    if (error != kAXErrorSuccess) {
        self.activationErrors++;
        NSLog(@"Cannot select Safari tab (%d)", error);
    }
    // Only the actually selected tab enters MRU, including when AXPress fails.
    [self synchronize];
}

- (void)switchBackward:(BOOL)backward timestamp:(EventTime)timestamp {
    // Focus can change between hotkey registration and delivery.
    if (![NSWorkspace.sharedWorkspace.frontmostApplication.bundleIdentifier isEqual:@"com.apple.Safari"]) {
        [self unregisterKeys];
        return;
    }
    if (!AXIsProcessTrusted()) {
        [self refresh];
        return;
    }
    self.keyPresses++;
    [self synchronize];
    if (!self.history.cycle) self.gestureStarted = timestamp;
    id target = [self.history stepBackward:backward];
    if (!target) return;
    [self registerCancelKeys];
    // The release event may precede delivery of a queued hotkey, even during a new chord.
    if (self.lastControlRelease >= timestamp ||
        !(CGEventSourceFlagsState(kCGEventSourceStateCombinedSessionState) & kCGEventFlagMaskControl)) {
        [self commitGesture];
    }
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL inspect = argc == 2 && strcmp(argv[1], "--inspect") == 0;
        if (argc > 1 && !inspect && strcmp(argv[1], "--request-access") != 0) {
            fprintf(stderr, "Usage: safari-mru [--inspect | --request-access]\n");
            return 2;
        }
        if (argc == 2 && strcmp(argv[1], "--request-access") == 0) {
            NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES};
            AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
            return 0;
        }
        if (inspect) {
            if (!AXIsProcessTrusted()) {
                fprintf(stderr, "Accessibility permission is required\n");
                return 1;
            }
            NSRunningApplication *safari = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.Safari"].firstObject;
            if (!safari) {
                fprintf(stderr, "Safari is not running\n");
                return 1;
            }
            id root = CFBridgingRelease(AXUIElementCreateApplication(safari.processIdentifier));
            id window = attribute(root, kAXFocusedWindowAttribute);
            NSArray *tabs = window ? tabsInWindow(window) : @[];
            printf("tabs=%lu selected=%s\n", (unsigned long)tabs.count, selectedTab(tabs) ? "yes" : "no");
            return tabs.count && selectedTab(tabs) ? 0 : 1;
        }
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
        SafariMRU *controller = [[SafariMRU alloc] init];
        signal(SIGINFO, SIG_IGN);
        controller.statusSignal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINFO, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(controller.statusSignal, ^{ [controller logStatus]; });
        dispatch_resume(controller.statusSignal);
        NSArray *workspaceNotifications = @[
            NSWorkspaceDidActivateApplicationNotification,
            NSWorkspaceDidLaunchApplicationNotification,
            NSWorkspaceDidTerminateApplicationNotification,
            NSWorkspaceDidWakeNotification,
            NSWorkspaceSessionDidBecomeActiveNotification,
            NSWorkspaceSessionDidResignActiveNotification,
            NSWorkspaceActiveSpaceDidChangeNotification,
        ];
        for (NSString *name in workspaceNotifications) {
            [NSWorkspace.sharedWorkspace.notificationCenter addObserverForName:name
                object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification) {
                    if ([notification.name isEqual:NSWorkspaceSessionDidResignActiveNotification]) {
                        controller.sessionInactive = YES;
                    } else if ([notification.name isEqual:NSWorkspaceSessionDidBecomeActiveNotification]) {
                        controller.sessionInactive = NO;
                    } else if ([notification.name isEqual:NSWorkspaceDidLaunchApplicationNotification] ||
                               [notification.name isEqual:NSWorkspaceDidTerminateApplicationNotification]) {
                        NSRunningApplication *app = notification.userInfo[NSWorkspaceApplicationKey];
                        if (![app.bundleIdentifier isEqual:@"com.apple.Safari"]) return;
                    }
                    [controller refresh];
                }];
        }
        [controller refresh];
        [controller logStatus];
        [NSApp run];
    }
    return 0;
}
