// fg-es tests — Endpoint Security degrade path (dev environment without entitlement, stub mode)
// The real ES path lands once the entitlement is in place (PRD Q#3: no entitlement → fall back to TCC)

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
    // Stub mode (no entitlement): start returns Degraded, not Active
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
    // stop must simply not panic (in stub mode the state is decided by cfg, not the active field)
    let _ = mon.status();
}
