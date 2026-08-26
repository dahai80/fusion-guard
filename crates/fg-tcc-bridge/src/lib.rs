#[cfg(tcc_bridge_stub)]
mod stub_enabled {}

extern "C" {
    fn fg_tcc_accessibility_status() -> i32;
    fn fg_tcc_screen_capture_status() -> i32;
    fn fg_tcc_microphone_status() -> i32;
    fn fg_tcc_camera_status() -> i32;
    fn fg_tcc_full_disk_access_status() -> i32;
    fn fg_tcc_apple_events_status() -> i32;
}

pub fn accessibility() -> bool {
    unsafe { fg_tcc_accessibility_status() == 1 }
}

pub fn screen_capture() -> bool {
    unsafe { fg_tcc_screen_capture_status() == 1 }
}

pub fn microphone() -> bool {
    unsafe { fg_tcc_microphone_status() == 1 }
}

pub fn camera() -> bool {
    unsafe { fg_tcc_camera_status() == 1 }
}

pub fn full_disk_access() -> bool {
    unsafe { fg_tcc_full_disk_access_status() == 1 }
}

pub fn apple_events() -> bool {
    unsafe { fg_tcc_apple_events_status() == 1 }
}
