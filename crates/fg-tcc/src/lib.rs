use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TccService {
    Accessibility,
    ScreenRecording,
    FullDiskAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccStatus {
    pub service: TccService,
    pub authorized: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccReport {
    pub statuses: Vec<TccStatus>,
}

pub fn query_status() -> Vec<TccStatus> {
    tracing::info!("querying TCC status via tccutil/db (status-only, no mutation)");
    vec![
        TccStatus {
            service: TccService::Accessibility,
            authorized: false,
            source: "tccutil:placeholder".to_string(),
        },
        TccStatus {
            service: TccService::ScreenRecording,
            authorized: false,
            source: "tccutil:placeholder".to_string(),
        },
        TccStatus {
            service: TccService::FullDiskAccess,
            authorized: false,
            source: "tccutil:placeholder".to_string(),
        },
    ]
}
