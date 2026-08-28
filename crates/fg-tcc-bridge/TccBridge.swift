import Foundation
import ApplicationServices
import CoreGraphics
import AVFoundation

@_cdecl("fg_tcc_accessibility_status")
public func fgTccAccessibilityStatus() -> Int32 {
    let trusted = AXIsProcessTrustedWithOptions(nil)
    return trusted ? 1 : 0
}

@_cdecl("fg_tcc_screen_capture_status")
public func fgTccScreenCaptureStatus() -> Int32 {
    if #available(macOS 10.15, *) {
        return CGPreflightScreenCaptureAccess() ? 1 : 0
    }
    return 0
}

@_cdecl("fg_tcc_microphone_status")
public func fgTccMicrophoneStatus() -> Int32 {
    if #available(macOS 10.14, *) {
        let status = AVCaptureDevice.authorizationStatus(for: .audio)
        return status == .authorized ? 1 : 0
    }
    return 0
}

@_cdecl("fg_tcc_camera_status")
public func fgTccCameraStatus() -> Int32 {
    if #available(macOS 10.14, *) {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        return status == .authorized ? 1 : 0
    }
    return 0
}

@_cdecl("fg_tcc_full_disk_access_status")
public func fgTccFullDiskAccessStatus() -> Int32 {
    let url = URL(fileURLWithPath: "/Library")
    do {
        let values = try url.resourceValues(forKeys: [.isReadableKey])
        return values.isReadable == true ? 1 : 0
    } catch {
        return 0
    }
}

// P1-6 (audit §P1-6): AppleEvents TCC 真实查询。
// guard 是 TCC 审计聚合方 (status-only), 非 AppleEvents 自动化发起方 ——
// AEDeterminePermissionToAutomateTarget 需目标 app 的 bundle/signature (per-target 授权),
// 守护进程无特定目标, 无法给单一布尔值。AEGetSystemOptToken 仅判系统级 AppleEvents 总开关,
// 非进程级 TCC DB 授权 (TCC.db kTCCServiceAppleEvents 按 sender-sserial/target-bookkeeping 粒度)。
// 故此处返 0 (未授权) 但 fg-tcc 标 source "apple-events:unknown" (非 live) —— 消费方见此知
// 该项未真实查询, 不误信为确定 false。真实 per-target 查询由 fusion-agent-studio (自动化发起方) 自报。
@_cdecl("fg_tcc_apple_events_status")
public func fgTccAppleEventsStatus() -> Int32 {
    return 0
}
