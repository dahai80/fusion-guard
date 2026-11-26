// fg-pyo3 build.rs — injects git_sha + build_time into the compile-time env vars
// Python __init__.py reads the __version__ metadata via _native.version_info()
// git_sha: `git rev-parse --short=8 HEAD` (no git or failure → "unknown", never blocks the build)
// build_time: build machine epoch seconds (Date::now is unavailable inside the workflow; build.rs is the right place)
use std::process::Command;

fn main() {
    // M5: rerun-if-changed must cover new commits on the same branch, not just branch switches.
    // Originally only .git/HEAD — HEAD stores the current branch name (not the commit hash), so a new commit on the same branch does not change the HEAD file contents
    // → FG_GIT_SHA went stale across incremental builds. Add .git/refs (includes refs/heads/<branch>, updated on each new commit) +
    // .git/packed-refs (ref index after packing). cargo ignores missing paths, never blocking the build.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
    println!("cargo:rerun-if-changed=../../.git/packed-refs");
    println!("cargo:rerun-if-changed=../../Cargo.toml");

    let git_sha = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FG_GIT_SHA={}", git_sha);

    let build_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=FG_BUILD_TIME={}", build_time);
}
