import Cocoa
import ApplicationServices
import Carbon

func value(_ e: AXUIElement, _ name: String) -> AnyObject? {
    var result: CFTypeRef?
    guard AXUIElementCopyAttributeValue(e, name as CFString, &result) == .success else { return nil }
    return result
}
func children(_ e: AXUIElement) -> [AXUIElement] { value(e, kAXChildrenAttribute) as? [AXUIElement] ?? [] }
func tabs(_ e: AXUIElement, _ depth: Int = 0) -> [AXUIElement] {
    if depth > 12 { return [] }
    if value(e, kAXSubroleAttribute) as? String == "AXTabButton" { return [e] }
    if ["AXWebArea", "AXScrollArea", "AXMenuBar", "AXOutline"].contains(value(e, kAXRoleAttribute) as? String ?? "") { return [] }
    return children(e).flatMap { tabs($0, depth + 1) }
}
func selected(_ tabs: [AXUIElement]) -> AXUIElement? {
    tabs.first { (value($0, kAXValueAttribute) as? NSNumber)?.boolValue == true }
}
func key(_ code: Int, _ down: Bool, _ flags: CGEventFlags = []) {
    let e = CGEvent(keyboardEventSource: nil, virtualKey: CGKeyCode(code), keyDown: down)!
    e.flags = flags
    e.post(tap: .cghidEventTap)
    Thread.sleep(forTimeInterval: 0.06)
}
func command(_ code: Int) throws {
    try check(NSWorkspace.shared.frontmostApplication?.bundleIdentifier == "com.apple.Safari", "Safari owns keyboard focus")
    key(55, true, .maskCommand); key(code, true, .maskCommand)
    key(code, false, .maskCommand); key(55, false)
    Thread.sleep(forTimeInterval: 0.35)
}
func wait() { Thread.sleep(forTimeInterval: 0.3) }
enum TestError: Error { case failed(String) }
func check(_ condition: Bool, _ message: String) throws {
    guard condition else { throw TestError.failed(message) }
    print("PASS: \(message)")
}

guard CommandLine.arguments.count == 2, AXIsProcessTrusted(),
      NSWorkspace.shared.frontmostApplication?.bundleIdentifier != "com.apple.loginwindow",
      let safari = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.Safari").first else {
    fputs("Usage: swift test-integration.swift /path/to/safari-mru (unlocked desktop; Safari running; Accessibility permission required)\n", stderr)
    exit(2)
}
let original = NSWorkspace.shared.frontmostApplication
let root = AXUIElementCreateApplication(safari.processIdentifier)
let oldWindows = value(root, kAXWindowsAttribute) as? [AXUIElement] ?? []
let oldFocusedWindow = value(root, kAXFocusedWindowAttribute)
var testWindow: AXUIElement?
var helper: Process?
do {
    defer {
        if testWindow != nil { key(56, false); key(59, false); key(55, false) }
        if let helper {
            if helper.isRunning { helper.terminate() }
            helper.waitUntilExit()
        }
        if let w = testWindow, let close = value(w, kAXCloseButtonAttribute) {
            _ = AXUIElementPerformAction(close as! AXUIElement, kAXPressAction as CFString)
        }
        if testWindow != nil {
            if let oldFocusedWindow { _ = AXUIElementPerformAction(oldFocusedWindow as! AXUIElement, kAXRaiseAction as CFString) }
            original?.activate(options: [])
        }
    }
    safari.activate(options: [])
    wait()
    try command(kVK_ANSI_N)
    let windows = value(root, kAXWindowsAttribute) as? [AXUIElement] ?? []
    testWindow = windows.first { w in !oldWindows.contains(where: { CFEqual($0, w) }) }
    try check(testWindow != nil, "created a separate test window")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: CommandLine.arguments[1])
    try process.run()
    helper = process
    Thread.sleep(forTimeInterval: 0.8)
    try command(kVK_ANSI_T); try command(kVK_ANSI_T)
    let t = Array(tabs(testWindow!).suffix(3))
    try check(t.count == 3, "tabs created after the helper starts are discovered")
    _ = AXUIElementPerformAction(t[0], kAXPressAction as CFString); wait()
    _ = AXUIElementPerformAction(t[1], kAXPressAction as CFString); wait()
    key(59, true, .maskControl)
    key(kVK_Tab, true, .maskControl); key(kVK_Tab, false, .maskControl); wait()
    try check(selected(t).map { CFEqual($0, t[0]) } ?? false, "Ctrl+Tab selects last used, not its neighbor")
    key(kVK_Tab, true, .maskControl); key(kVK_Tab, false, .maskControl); wait()
    try check(selected(t).map { CFEqual($0, t[2]) } ?? false, "holding Ctrl reaches the third MRU tab")
    key(56, true, [.maskControl, .maskShift])
    key(kVK_Tab, true, [.maskControl, .maskShift]); key(kVK_Tab, false, [.maskControl, .maskShift]); wait()
    try check(selected(t).map { CFEqual($0, t[0]) } ?? false, "Ctrl+Shift+Tab reverses the held cycle")
    key(56, false, .maskControl); key(59, false); wait()
    key(59, true, .maskControl)
    key(kVK_Tab, true, .maskControl); key(kVK_Tab, false, .maskControl)
    key(59, false); wait()
    try check(selected(t).map { CFEqual($0, t[1]) } ?? false, "release then tap returns to the original tab")
    try command(kVK_ANSI_L)
    key(59, true, .maskControl)
    key(kVK_Tab, true, .maskControl); key(kVK_Tab, false, .maskControl)
    key(59, false); wait()
    try check(selected(t).map { CFEqual($0, t[0]) } ?? false, "switching works with the address bar focused")
    _ = AXUIElementPerformAction(t[2], kAXPressAction as CFString); wait()
    try command(kVK_ANSI_W)
    key(59, true, .maskControl)
    key(kVK_Tab, true, .maskControl); key(kVK_Tab, false, .maskControl)
    key(59, false); wait()
    try check(selected(Array(t.prefix(2))).map { CFEqual($0, t[0]) } ?? false, "closing a tab removes it from MRU")
    if let other = NSRunningApplication.runningApplications(withBundleIdentifier: "com.superlogical.rex").first {
        other.activate(options: []); wait()
        var probe: EventHotKeyRef?
        let status = RegisterEventHotKey(UInt32(kVK_Tab), UInt32(controlKey),
            EventHotKeyID(signature: 0x54455354, id: 99), GetApplicationEventTarget(),
            OptionBits(kEventHotKeyExclusive), &probe)
        if let probe { UnregisterEventHotKey(probe) }
        try check(status == noErr, "Ctrl+Tab is released outside Safari")
        safari.activate(options: [])
        _ = AXUIElementPerformAction(testWindow!, kAXRaiseAction as CFString); wait()
        key(59, true, .maskControl)
        key(kVK_Tab, true, .maskControl); key(kVK_Tab, false, .maskControl)
        key(59, false); wait()
        try check(selected(Array(t.prefix(2))).map { CFEqual($0, t[1]) } ?? false, "MRU survives switching to another app and back")
    }
    try check(NSRunningApplication(processIdentifier: process.processIdentifier)?.activationPolicy == .prohibited,
              "helper has no Dock icon or active application UI")
    print("Native Safari MRU integration passed")
} catch {
    fputs("FAIL: \(error)\n", stderr)
    exit(1)
}
