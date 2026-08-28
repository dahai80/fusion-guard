// fg-es 测试 — Endpoint Security 降级路径 (无 entitlement 开发环境, stub 模式)
// 真实 ES 路径待 entitlement 就位 (PRD Q#3: 无 entitlement → 降级 TCC)

use fg_es::{default_kinds, EsEventKind, EsMonitor, EsMonitorState, EsStatus};

#[test]
fn event_kind_roundtrip() {
    for k in default_kinds() {
        let s = k.as_str();
        assert_eq!(EsEventKind::parse(s), Some(k));
    }
    assert_eq!(EsEventKind::parse("bogus"), None);
}

#[test]
fn monitor_degraded_without_entitlement() {
    // stub 模式 (无 entitlement): start 返回 Degraded, 非 Active
    let mut mon = EsMonitor::new(default_kinds());
    let status = mon.start();
    assert_eq!(status.state, EsMonitorState::Degraded);
    assert!(!status.entitlement);
    assert_eq!(status.source, "es-bridge:stub");
    assert!(status.subscribed.is_empty());
}

#[test]
fn degraded_monitor_no_events() {
    let mon = EsMonitor::new(default_kinds());
    let events = mon.monitor_events();
    assert!(events.is_empty(), "degraded stub mode yields no events");
}

#[test]
fn status_reflects_stub() {
    let mon = EsMonitor::new(vec![EsEventKind::Exec, EsEventKind::Unlink]);
    let s = mon.status();
    assert_eq!(s.state, EsMonitorState::Degraded);
    assert!(!s.entitlement);
}

#[test]
fn es_status_degraded_constructor() {
    let s = EsStatus::degraded();
    assert_eq!(s.state, EsMonitorState::Degraded);
    assert!(!s.entitlement);
    assert_eq!(s.source, "es-bridge:stub");
}

#[test]
fn stop_clears() {
    let mut mon = EsMonitor::new(default_kinds());
    mon.stop();
    // stop 无 panic 即可 (stub 模式 state 由 cfg 决定, 非 active 字段)
    let _ = mon.status();
}
