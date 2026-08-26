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

pub fn tokenize_check(content: &str) -> Option<TokenHit> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(reason) = check_shell_substitution(trimmed) {
        return Some(TokenHit {
            binary: String::new(),
            reason,
            stage: CheckStage::Ast,
            sensitive_target: false,
        });
    }
    for segment in split_chain(trimmed) {
        let seg = segment.trim();
        if seg.is_empty() {
            continue;
        }
        if let Some(hit) = check_segment(seg) {
            return Some(hit);
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
    if !WHITELIST.contains(&binary_basename.as_str()) {
        return Some(TokenHit {
            binary: binary_basename.clone(),
            reason: format!("二进制程序不在白名单: {}", binary),
            stage: CheckStage::Ast,
            sensitive_target: false,
        });
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

fn check_argv(binary: &str, args: &[String]) -> Option<String> {
    match binary {
        "mv" | "cp" => {
            let dest = args
                .iter()
                .rev()
                .find(|a| !a.starts_with('-') && !a.starts_with('>'));
            if let Some(dest) = dest {
                if is_sensitive_path(dest) {
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
                    return Some(format!(
                        "{} 读源为凭据文件 (敏感文件名模式): {}",
                        binary, a
                    ));
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

fn check_redirect_target(segment: &str) -> Option<String> {
    let re = regex::Regex::new(r">\s*([^\s|&;]+)").ok()?;
    for cap in re.captures_iter(segment) {
        if let Some(target) = cap.get(1) {
            if is_sensitive_path(target.as_str()) {
                return Some(format!(
                    "重定向目标位于敏感路径: {}",
                    target.as_str()
                ));
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
