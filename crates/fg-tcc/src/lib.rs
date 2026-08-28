use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TccService {
    Accessibility,
    ScreenRecording,
    FullDiskAccess,
    Microphone,
    Camera,
    AppleEvents,
}

impl TccService {
    pub fn as_str(&self) -> &'static str {
        match self {
            TccService::Accessibility => "accessibility",
            TccService::ScreenRecording => "screen_capture",
            TccService::FullDiskAccess => "full_disk_access",
            TccService::Microphone => "microphone",
            TccService::Camera => "camera",
            TccService::AppleEvents => "apple_events",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "accessibility" => Some(TccService::Accessibility),
            "screen_capture" | "screen_recording" => Some(TccService::ScreenRecording),
            "full_disk_access" => Some(TccService::FullDiskAccess),
            "microphone" => Some(TccService::Microphone),
            "camera" => Some(TccService::Camera),
            "apple_events" => Some(TccService::AppleEvents),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccStatus {
    pub service: TccService,
    pub authorized: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccEvent {
    pub permission: String,
    pub requester: String,
    pub result: String,
    pub reason: String,
    pub ts: i64,
}

pub fn query_status() -> Vec<TccStatus> {
    tracing::info!("querying TCC status via Swift bridge (status-only, no mutation)");
    let stub = cfg!(tcc_bridge_stub);
    let source = if stub {
        "tccutil:stub".to_string()
    } else {
        "swift-bridge:live".to_string()
    };
    vec![
        TccStatus {
            service: TccService::Accessibility,
            authorized: fg_tcc_bridge::accessibility(),
            source: source.clone(),
        },
        TccStatus {
            service: TccService::ScreenRecording,
            authorized: fg_tcc_bridge::screen_capture(),
            source: source.clone(),
        },
        TccStatus {
            service: TccService::FullDiskAccess,
            authorized: fg_tcc_bridge::full_disk_access(),
            source: source.clone(),
        },
        TccStatus {
            service: TccService::Microphone,
            authorized: fg_tcc_bridge::microphone(),
            source: source.clone(),
        },
        TccStatus {
            service: TccService::Camera,
            authorized: fg_tcc_bridge::camera(),
            source: source.clone(),
        },
        // P1-6 (audit §P1-6): AppleEvents 真实查询。
        // Swift bridge fg_tcc_apple_events_status 恒返 0 —— guard 非 AppleEvents 自动化发起方,
        // 无特定目标 app, 无法给单一布尔值 (TCC.db kTCCServiceAppleEvents 按 sender/target 粒度)。
        // live 路径标 source "apple-events:unknown" (非 live), authorized=false —— 消费方见此知
        // 该项未真实查询, 不误信为确定 false。真实 per-target 查询由自动化发起方 (agent-studio) 自报。
        // stub 路径全桥为 stub, source 仍 tccutil:stub。
        TccStatus {
            service: TccService::AppleEvents,
            authorized: fg_tcc_bridge::apple_events(),
            source: if stub {
                "tccutil:stub".to_string()
            } else {
                "apple-events:unknown".to_string()
            },
        },
    ]
}
