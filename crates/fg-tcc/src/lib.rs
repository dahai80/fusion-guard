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
        // P1-6 (audit §P1-6): AppleEvents honest query.
        // The Swift bridge fg_tcc_apple_events_status always returns 0 — guard is not the
        // AppleEvents automation initiator, has no specific target app, and cannot yield a single
        // boolean (TCC.db kTCCServiceAppleEvents is scoped per sender/target).
        // The live path tags source "apple-events:unknown" (not live), authorized=false —
        // consumers seeing this know the item was not truly queried and do not mistake it for a
        // definite false. Real per-target queries are self-reported by the automation initiator
        // (agent-studio).
        // On the stub path the whole bridge is a stub; source stays tccutil:stub.
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
