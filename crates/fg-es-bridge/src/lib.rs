// fg-es-bridge — Endpoint Security C FFI bridge (PRD Phase 7, Q#3)
//
// The macOS Endpoint Security framework is a C API (EndpointSecurity/EndpointSecurity.h):
//   ESNewClient / ESSubscribe / ESDeleteClient / ESReturn
// Real use requires the com.apple.developer.endpoint-security.client entitlement (Apple developer agreement).
//
// This crate is the sole unsafe_code=allow ES FFI crate (mirrors the fg-tcc-bridge pattern).
// build.rs detects the entitlement/compile environment → if absent emits cfg(es_bridge_stub) + a C stub fallback
// (es_new_client returns 0 = fail-degrade, event functions return empty); fg-es takes the Degraded path accordingly.
//
// Currently landed (dev environment without entitlement): stub mode — FFI symbols link to C stubs (all return 0/empty);
// the real ES C binding lands once the entitlement is in place (never pulling in an unlicensed framework).

#[cfg(es_bridge_stub)]
mod stub_enabled {}

extern "C" {
    // Returns 1 = client created successfully (active), 0 = failure (degraded, no entitlement)
    fn fg_es_new_client() -> i32;
    // Returns the number of captured events (stub=0)
    fn fg_es_event_count() -> i32;
}

// Pass the stub state through to fg-es (the cfg is only visible inside this crate, so expose it to dependents via a function)
pub fn is_stub() -> bool {
    cfg!(es_bridge_stub)
}

pub fn new_client() -> bool {
    unsafe { fg_es_new_client() == 1 }
}

pub fn event_count() -> i32 {
    unsafe { fg_es_event_count() }
}
