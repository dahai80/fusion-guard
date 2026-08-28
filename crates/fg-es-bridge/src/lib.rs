// fg-es-bridge — Endpoint Security C FFI 桥 (PRD Phase 7, Q#3)
//
// macOS Endpoint Security framework 是 C API (EndpointSecurity/EndpointSecurity.h):
//   ESNewClient / ESSubscribe / ESDeleteClient / ESReturn
// 真实使用需 com.apple.developer.endpoint-security.client entitlement (Apple 签约)。
//
// 本 crate 为唯一 unsafe_code=allow 的 ES FFI crate (镜像 fg-tcc-bridge 范式)。
// build.rs 检测 entitlement/编译环境 → 无则发 cfg(es_bridge_stub) + C stub fallback
// (es_new_client 返回 0=失败降级, 事件函数返回空), fg-es 据此走 Degraded 路径。
//
// 当前落地 (开发环境无 entitlement): stub 模式 — FFI 符号链接 C stub (全返回 0/空),
// 真实 ES C 绑定待 entitlement 就位后接入 (不引未授权 framework)。

#[cfg(es_bridge_stub)]
mod stub_enabled {}

extern "C" {
    // 返回 1=client 创建成功 (active), 0=失败 (degraded, 无 entitlement)
    fn fg_es_new_client() -> i32;
    // 返回已捕获事件数 (stub=0)
    fn fg_es_event_count() -> i32;
}

// stub 状态透传给 fg-es (cfg 只在本 crate 可见, 用函数暴露给依赖方)
pub fn is_stub() -> bool {
    cfg!(es_bridge_stub)
}

pub fn new_client() -> bool {
    unsafe { fg_es_new_client() == 1 }
}

pub fn event_count() -> i32 {
    unsafe { fg_es_event_count() }
}
