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

@_cdecl("fg_tcc_apple_events_status")
public func fgTccAppleEventsStatus() -> Int32 {
    return 0
}
