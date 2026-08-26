use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let swift_src = manifest.join("TccBridge.swift");
    let obj = out_dir.join("TccBridge.o");
    let lib = out_dir.join("libfgtccbridge.a");

    let swiftc = std::env::var("SWIFTC").unwrap_or_else(|_| "swiftc".to_string());

    let emit = Command::new(&swiftc)
        .args([
            "-emit-object",
            "-o",
            obj.to_str().unwrap(),
            "-target",
            "arm64-apple-macosx13.0",
            swift_src.to_str().unwrap(),
        ])
        .output();

    let mut stub_mode = false;
    match emit {
        Ok(out) if out.status.success() => {
            println!("cargo:warning=swift bridge compiled (live TCC status)");
        }
        _ => {
            stub_mode = true;
            println!("cargo:warning=swift compile unavailable; using C stub fallback");
            let stub = out_dir.join("tcc_stub.c");
            std::fs::write(
                &stub,
                "int fg_tcc_accessibility_status(){return 0;}\n\
                 int fg_tcc_screen_capture_status(){return 0;}\n\
                 int fg_tcc_microphone_status(){return 0;}\n\
                 int fg_tcc_camera_status(){return 0;}\n\
                 int fg_tcc_full_disk_access_status(){return 0;}\n\
                 int fg_tcc_apple_events_status(){return 0;}\n",
            )
            .expect("write stub");
            let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
            let _ = Command::new(&cc)
                .args(["-c", "-o", obj.to_str().unwrap(), stub.to_str().unwrap()])
                .status();
        }
    }

    let ar = std::env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let _ = Command::new(&ar)
        .args(["rcs", lib.to_str().unwrap(), obj.to_str().unwrap()])
        .status();

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=fgtccbridge");

    if stub_mode {
        println!("cargo:rustc-cfg=tcc_bridge_stub");
    } else {
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=AVFoundation");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }

    println!("cargo:rerun-if-changed=TccBridge.swift");
}
