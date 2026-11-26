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
        // P1-6: the AppleEvents live path tags "apple-events:unknown" (not live; the bridge always
        // returns 0, not a real query).
        // Three legal states: swift-bridge:live (5 services truly queried) / tccutil:stub (whole
        // bridge stubbed) / apple-events:unknown.
        assert!(
            s.source == "swift-bridge:live"
                || s.source == "tccutil:stub"
                || s.source == "apple-events:unknown",
            "unexpected source tag: {}",
            s.source
        );
    }
}

// P1-6 (audit §P1-6): AppleEvents honest query regression.
// The Swift bridge always returns 0 (guard is not the AE automation initiator, has no target app,
// and cannot yield a single boolean).
// The live path (non-stub) must tag source "apple-events:unknown" (not live), never misreporting
// a definite false.
// authorized=false because the bridge returns 0; source distinguishes "not queried" from
// "queried and not authorized".
#[test]
fn query_status_apple_events_marked_unknown_live() {
    let statuses = query_status();
    let ae = statuses
        .iter()
        .find(|s| s.service == TccService::AppleEvents)
        .expect("AppleEvents service present");
    // Live path (cfg!(tcc_bridge_stub)==false) must be tagged unknown, not live.
    if !cfg!(tcc_bridge_stub) {
        assert_eq!(
            ae.source, "apple-events:unknown",
            "P1-6: live-path AppleEvents must be tagged apple-events:unknown (bridge always returns 0, not a real query), not swift-bridge:live"
        );
        assert!(
            !ae.authorized,
            "P1-6: AppleEvents bridge always returns 0 → authorized=false"
        );
    } else {
        // Stub path: whole bridge stubbed, source=tccutil:stub (P1-6 does not change stub behavior).
        assert_eq!(
            ae.source, "tccutil:stub",
            "P1-6: stub-path AppleEvents stays tccutil:stub"
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
