// fg-pyo3 build.rs — 注入 git_sha + build_time 到编译环境变量
// Python __init__.py 经 _native.version_info() 读 __version__ 元信息
// git_sha: `git rev-parse --short=8 HEAD` (无 git 或失败 → "unknown", 不阻断构建)
// build_time: 编译机 epoch 秒 (workflow 内 Date::now 不可用, build.rs 正常)
use std::process::Command;

fn main() {
    // M5: rerun-if-changed 须覆盖同分支新提交, 非仅分支切换。
    // 原 仅 .git/HEAD —— HEAD 存当前分支名 (非 commit hash), 同分支新提交不改 HEAD 文件内容
    // → FG_GIT_SHA 增量构建陈旧。补 .git/refs (含 refs/heads/<branch>, 新提交更新该文件) +
    // .git/packed-refs (pack 后 ref 索引)。无对应路径 cargo 忽略, 不阻断构建。
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
