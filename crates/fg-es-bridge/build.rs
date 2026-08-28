// fg-es-bridge build.rs — Endpoint Security FFI 编译策略
//
// macOS ES framework (EndpointSecurity.framework) 真实链接需:
//   1. framework 存在 (macOS 12+)
//   2. com.apple.developer.endpoint-security.client entitlement (Apple 签约)
// 开发环境无 entitlement → 链 ES framework 会运行时失败 (ESNewClient 拒绝)。
//
// 策略 (镜像 fg-tcc-bridge stub 范式):
//   - 默认 stub 模式: 编 C stub (符号全返回 0/空), 发 cfg(es_bridge_stub)
//     fg-es 据此走 Degraded 路径 (退回 TCC, PRD Q#3)
//   - entitlement 就位后: 设 FUSION_GUARD_ES_LIVE=1 环境变量
//     build.rs 链 ES framework + 编真实 FFI (待 entitlement 落地)
//
// 当前恒 stub (无 entitlement 开发环境) — 真实绑定待资质就位。

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let obj = out_dir.join("EsBridge.o");
    let lib = out_dir.join("libfgesbridge.a");

    // 真实 ES 路径需显式 opt-in (entitlement 就位后): FUSION_GUARD_ES_LIVE=1
    let live = std::env::var("FUSION_GUARD_ES_LIVE")
        .map(|v| v == "1")
        .unwrap_or(false);

    if live {
        // 真实 ES C 绑定 (需 entitlement + provisioning, 此处占位待接入)
        // 当前不编真实 FFI — entitlement 未就位前留空, 防未授权链接 ES framework
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
        "// ES stub — 无 entitlement 降级, 全返回 0/空 (fg-es 走 Degraded)\n\
         int fg_es_new_client(void){return 0;}\n\
         int fg_es_event_count(void){return 0;}\n",
    )
    .expect("write es stub");
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    // M7: 勿吞 cc 编译失败 (原 let _ = status())。stub .o 缺失 → ar 打包空 → 链接报错不清晰。
    let cc_status = Command::new(&cc)
        .args(["-c", "-o", obj.to_str().unwrap(), stub.to_str().unwrap()])
        .status()
        .unwrap_or_else(|e| panic!("cc es stub compile failed to start: {e}"));
    if !cc_status.success() {
        panic!("cc es stub compile failed (exit {:?})", cc_status.code());
    }
    let ar = std::env::var("AR").unwrap_or_else(|_| "ar".to_string());
    // M7: ar 打包失败显式 fail, 非静默吞。
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
