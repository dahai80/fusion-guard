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
        // P1-6: AppleEvents live 路径标 "apple-events:unknown" (非 live, 桥恒返 0 非真实查询)。
        // 三态合法: swift-bridge:live (5 服务真实查) / tccutil:stub (全桥 stub) / apple-events:unknown。
        assert!(
            s.source == "swift-bridge:live"
                || s.source == "tccutil:stub"
                || s.source == "apple-events:unknown",
            "unexpected source tag: {}",
            s.source
        );
    }
}

// P1-6 (audit §P1-6): AppleEvents 真实查询回归。
// Swift bridge 恒返 0 (guard 非 AE 自动化发起方, 无目标 app, 无法给单一布尔值)。
// live 路径 (非 stub) 须标 source "apple-events:unknown" (非 live), 不误报为确定 false。
// authorized=false 因桥返 0; source 区分 "未查" vs "查了且未授权"。
#[test]
fn query_status_apple_events_marked_unknown_live() {
    let statuses = query_status();
    let ae = statuses
        .iter()
        .find(|s| s.service == TccService::AppleEvents)
        .expect("AppleEvents service present");
    // live 路径 (cfg!(tcc_bridge_stub)==false) 须标 unknown, 非 live。
    if !cfg!(tcc_bridge_stub) {
        assert_eq!(
            ae.source, "apple-events:unknown",
            "P1-6: live 路径 AppleEvents 须标 apple-events:unknown (桥恒返 0 非真实查询), 非 swift-bridge:live"
        );
        assert!(
            !ae.authorized,
            "P1-6: AppleEvents 桥恒返 0 → authorized=false"
        );
    } else {
        // stub 路径全桥为 stub, source=tccutil:stub (P1-6 不改变 stub 行为)。
        assert_eq!(
            ae.source, "tccutil:stub",
            "P1-6: stub 路径 AppleEvents 仍 tccutil:stub"
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
