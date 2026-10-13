// lidguard — 事件驱动版
//   开盖：disablesleep 1，取消计时
//   合盖：开始 GRACE 秒倒计时，到点 disablesleep 0 + sleepnow；期间开盖则取消
//   合盖时切到电池：立即睡眠
//   退出（SIGTERM/SIGINT）：恢复 disablesleep 0
// 触发源：IOPMrootDomain 的合盖消息 + 电源切换通知，无轮询。
// 需要 root 运行。

import Foundation
import IOKit
import IOKit.ps

setvbuf(stdout, nil, _IOLBF, 0)

let grace: TimeInterval = ProcessInfo.processInfo.environment["GRACE"].flatMap(Double.init) ?? 1800

func log(_ msg: String) {
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm:ss"
    print("\(f.string(from: Date())) \(msg)")
}

// ---------- 状态读取 ----------

let rootDomain = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPMrootDomain"))
guard rootDomain != 0 else { log("IOPMrootDomain not found"); exit(1) }

func lidClosed() -> Bool {
    guard let v = IORegistryEntryCreateCFProperty(rootDomain, "AppleClamshellState" as CFString,
                                                  kCFAllocatorDefault, 0)?.takeRetainedValue()
    else { return false }
    return (v as? Bool) ?? false
}

func onAC() -> Bool {
    let info = IOPSCopyPowerSourcesInfo().takeRetainedValue()
    guard let type = IOPSGetProvidingPowerSourceType(info)?.takeUnretainedValue() else { return true }
    return (type as String) == "AC Power"
}

// ---------- 动作 ----------

@discardableResult
func pmset(_ args: String...) -> Int32 {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/pmset")
    p.arguments = args
    do { try p.run(); p.waitUntilExit(); return p.terminationStatus }
    catch { log("pmset \(args) failed: \(error)"); return -1 }
}

var sleepDisabled: Bool? = nil
func setDisableSleep(_ on: Bool) {
    guard sleepDisabled != on else { return }
    pmset("-a", "disablesleep", on ? "1" : "0")
    sleepDisabled = on
    log("disablesleep -> \(on ? 1 : 0)")
}

var graceTimer: Timer?
var slept = false

func goToSleep(_ why: String) {
    graceTimer?.invalidate(); graceTimer = nil
    slept = true
    setDisableSleep(false)
    log("sleep now (\(why))")
    pmset("sleepnow")
}

// ---------- 状态机：每个事件都重新评估一次 ----------

func evaluate(_ trigger: String) {
    if !lidClosed() {
        if graceTimer != nil || slept { log("lid open (\(trigger)), timer reset") }
        graceTimer?.invalidate(); graceTimer = nil
        slept = false
        setDisableSleep(true)
        return
    }
    if slept { return }
    if !onAC() { goToSleep("on battery"); return }
    if graceTimer == nil {
        log("lid closed (\(trigger)), sleeping in \(Int(grace))s")
        graceTimer = Timer.scheduledTimer(withTimeInterval: grace, repeats: false) { _ in
            graceTimer = nil
            goToSleep("grace expired")
        }
    }
}

// ---------- 事件注册 ----------

// 1) 合盖/开盖：IOPMrootDomain general interest 消息
//    kIOPMMessageClamshellStateChange = iokit_family_msg(sub_iokit_powermanagement, 0x100)
let kClamshellStateChange: natural_t = 0xE003_4100

let notifyPort = IONotificationPortCreate(kIOMainPortDefault)
CFRunLoopAddSource(CFRunLoopGetMain(),
                   IONotificationPortGetRunLoopSource(notifyPort).takeUnretainedValue(),
                   .defaultMode)
var interestNotifier: io_object_t = 0
let kr = IOServiceAddInterestNotification(notifyPort, rootDomain, "IOGeneralInterest",
    { _, _, messageType, _ in
        if messageType == kClamshellStateChange { evaluate("clamshell event") }
    }, nil, &interestNotifier)
guard kr == KERN_SUCCESS else { log("IOServiceAddInterestNotification failed: \(kr)"); exit(1) }

// 2) 电源切换（插拔电源）
let psSource = IOPSNotificationCreateRunLoopSource({ _ in evaluate("power source") }, nil).takeRetainedValue()
CFRunLoopAddSource(CFRunLoopGetMain(), psSource, .defaultMode)

// 3) 退出时恢复正常睡眠
signal(SIGTERM, SIG_IGN)
signal(SIGINT, SIG_IGN)
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    s.setEventHandler {
        pmset("-a", "disablesleep", "0")
        log("exit, disablesleep -> 0")
        exit(0)
    }
    s.resume()
    signalSources.append(s)
}

log("start (GRACE=\(Int(grace))s)")
evaluate("startup")
RunLoop.main.run()
