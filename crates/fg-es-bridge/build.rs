// fg-es-bridge build.rs — Endpoint Security FFI compile strategy
//
// Really linking the macOS ES framework (EndpointSecurity.framework) requires:
//   1. the framework present (macOS 12+)
//   2. the com.apple.developer.endpoint-security.client entitlement (Apple developer agreement)
// A dev environment without the entitlement → linking the ES framework fails at runtime (ESNewClient refuses).
//
// Strategy (mirrors the fg-tcc-bridge stub pattern):
//   - Default stub mode: compile a C stub (symbols all return 0/empty), emit cfg(es_bridge_stub);
//     fg-es takes the Degraded path accordingly (fall back to TCC, PRD Q#3)
//   - Once the entitlement is in place: set the FUSION_GUARD_ES_LIVE=1 env var
//     and build.rs links the ES framework + compiles the real FFI (pending entitlement provisioning)
//
// Currently always stub (dev environment without entitlement) — the real binding awaits provisioning.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out_dir.join("EsBridge.o");
    let lib = out_dir.join("libfgesbridge.a");

    // The real ES path requires explicit opt-in (once the entitlement is in place): FUSION_GUARD_ES_LIVE=1
    let live = std::env::var("FUSION_GUARD_ES_LIVE")
        .map(|v| v == "1")
        .unwrap_or(false);

    if live {
        // Real ES C binding (requires entitlement + provisioning; placeholder here pending integration)
        // Currently no real FFI is compiled — left empty until the entitlement is provisioned, preventing unauthorized ES framework linking
        println!("cargo:warning=ES live mode requested but entitlement not provisioned; falling back to stub");
        compile_stub(&out_dir, &obj, &lib);
        println!("cargo:rustc-cfg=es_bridge_stub");
    } else {
        println!("cargo:warning=ES bridge stub mode (no entitlement; degraded → TCC, PRD Q#3)");
        compile_stub(&out_dir, &obj, &lib);
        println!("cargo:rustc-cfg=es_bridge_stub");
    }

    println!("cargo:rerun-if-env-changed=FUSION_GUARD_ES_LIVE");
}

fn compile_stub(out_dir: &std::path::Path, obj: &std::path::Path, lib: &std::path::Path) {
    let stub = out_dir.join("es_stub.c");
    std::fs::write(
        &stub,
        "// ES stub — degrade without entitlement; all symbols return 0/empty (fg-es takes the Degraded path)\n\
         int fg_es_new_client(void){return 0;}\n\
         int fg_es_event_count(void){return 0;}\n",
    )
    .expect("write es stub");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    // M7: never swallow cc compile failures (originally let _ = status()). A missing stub .o → ar packs nothing → unclear link errors.
    let cc_status = Command::new(&cc)
        .args(["-c", "-o", obj.to_str().unwrap(), stub.to_str().unwrap()])
        .status()
        .unwrap_or_else(|e| panic!("cc es stub compile failed to start: {e}"));
    if !cc_status.success() {
        panic!("cc es stub compile failed (exit {:?})", cc_status.code());
    }
    let ar = std::env::var("AR").unwrap_or_else(|_| "ar".to_string());
    // M7: fail explicitly on ar archive failure, never silently swallow it.
    let ar_status = Command::new(&ar)
        .args(["rcs", lib.to_str().unwrap(), obj.to_str().unwrap()])
        .status()
        .unwrap_or_else(|e| panic!("ar es archive failed to start: {e}"));
    if !ar_status.success() {
        panic!("ar es archive failed (exit {:?})", ar_status.code());
    }
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=fgesbridge");
}
