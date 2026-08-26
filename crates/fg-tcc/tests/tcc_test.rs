use fg_tcc::{query_status, TccService};

#[test]
fn tcc_service_roundtrip() {
    for s in [
        TccService::Accessibility,
        TccService::ScreenRecording,
        TccService::FullDiskAccess,
        TccService::Microphone,
        TccService::Camera,
        TccService::AppleEvents,
    ] {
        let s2 = TccService::parse(s.as_str()).expect("roundtrip");
        assert_eq!(s, s2, "service roundtrip failed for {:?}", s);
    }
}

#[test]
fn tcc_service_screen_recording_alias() {
    assert_eq!(
        TccService::parse("screen_recording"),
        Some(TccService::ScreenRecording)
    );
}

#[test]
fn tcc_service_unknown_returns_none() {
    assert!(TccService::parse("nope").is_none());
}

#[test]
fn query_status_returns_six_services() {
    let statuses = query_status();
    assert_eq!(statuses.len(), 6, "expected 6 TCC services");
    let services: Vec<_> = statuses.iter().map(|s| s.service).collect();
    assert!(services.contains(&TccService::Accessibility));
    assert!(services.contains(&TccService::ScreenRecording));
    assert!(services.contains(&TccService::FullDiskAccess));
    assert!(services.contains(&TccService::Microphone));
    assert!(services.contains(&TccService::Camera));
    assert!(services.contains(&TccService::AppleEvents));
}

#[test]
fn query_status_source_tagged() {
    let statuses = query_status();
    for s in &statuses {
        assert!(
            s.source == "swift-bridge:live" || s.source == "tccutil:stub",
            "unexpected source tag: {}",
            s.source
        );
    }
}

#[test]
fn query_status_authorized_is_bool() {
    let statuses = query_status();
    for s in &statuses {
        let _ = s.authorized;
    }
}
