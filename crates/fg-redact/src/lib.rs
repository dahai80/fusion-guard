use regex::Regex;
use std::cmp::Reverse;
use std::sync::OnceLock;
use uuid::Uuid;

// M4: 编译失败不再 panic (原 4× .unwrap()), 返 Result 由 AuditEngine::new 决策 (fail-closed)。
// P2: redact_counted 单次遍历返 (String, hit_count) —— evaluate 跳独立 has_sensitive 二扫。
// P1-1 (audit §1.10): DLP 脱敏盲区扩展 —— 新增 AWS Secret/JWT/OAuth bearer/信用卡 (Luhn)/
// 手机号/GCP/Azure/Stripe key/连接串内嵌凭据/.env 风格泛化 KEY=value。模式带可选 validator
// (规则 5: Luhn/字符集等确定性校验用代码非模型), validator 返 false 的候选 span 跳过。
pub struct Redactor {
    patterns: Vec<PatternDef>,
}

struct PatternDef {
    name: &'static str,
    re: Regex,
    // P1-1 (规则 5): validator 接收 (content, span起, span止) —— 正则无 lookaround (regex crate),
    // 边界 (前后非同类字符) + Luhn + 字符多样性 用代码校验, 非模型非正则。
    validator: Option<ValidatorFn>,
}

type ValidatorFn = fn(&str, usize, usize) -> bool;

pub struct ReversibleMatch {
    pub placeholder: String,
    pub token_id: String,
    pub original: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    #[error("redact regex compile failed: {0}")]
    Regex(#[from] regex::Error),
}

struct AcceptedMatch {
    start: usize,
    end: usize,
    name_tag: &'static str,
    value: String,
}

impl Redactor {
    // C19: 脱敏正则覆盖真实密钥编码, 非玩具输入。
    // P1-1 (audit §1.10): 扩展 DLP 覆盖面 —— AWS Secret/JWT/OAuth bearer/信用卡 (Luhn)/
    //   手机号/GCP/Azure/Stripe/连接串内嵌凭据/.env 泛化 KEY=value。
    // 顺序关键: 长凭据 + 重叠数字模式必须先于 id_number (\d{17}[\dXx]) —— 否则 40 位 AWS Secret
    //   或 13-19 位信用卡被 id_number 的 17 位数字子串吞。先到先拒重叠 (collect_spans 语义),
    //   故越具体/越长的越靠前。
    // 每个模式组 1 (若有) = 敏感值; 无组 1 (PEM 块/OpenSSH/JWT/bearer/credit card/phone) = 全匹配。
    // 通用键值模式仅脱敏值, 保留字段名 (DLP 惯例: 标签可见, 机密脱敏)。
    // M4: 返 Result, 编译失败可 fail-closed (非 process panic)。
    // 规则 5: Luhn (信用卡) + base64 字符集多样性 (AWS Secret) 用代码 validator, 非正则非模型。
    pub fn new() -> std::result::Result<Self, RedactError> {
        // (name, pattern, optional_validator)
        let defs: [(&'static str, &str, Option<ValidatorFn>); 15] = [
            // PEM 块 / OpenSSH / JWK —— 多行, 最高优先, 不与短模式重叠。
            (
                "private_key",
                r#"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----|ssh-(?:rsa|ed25519|ecdsa) [A-Za-z0-9+/=]+|"(?:d|p|q|k|n)":\s*"[^"]+""#,
                None,
            ),
            // JWT 三段式 (eyJ… . eyJ… . …) —— base64url, 全匹配。先于裸数字模式 (防 17+ 数字子串误吞)。
            (
                "jwt",
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                None,
            ),
            // OAuth bearer token (Authorization: Bearer …) —— 组 1 = token 值, 前缀 "Bearer " 保留可见。
            (
                "oauth_bearer",
                r"(?i)bearer\s+([A-Za-z0-9_\-\.=~:/+]+)",
                None,
            ),
            // GCP ya29 / Azure AIza / Stripe sk_live/sk_test + 原 API key 变体。
            (
                "api_key",
                r"(?i)(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|ya29\.[A-Za-z0-9_\-]{20,}|api[_-]?key\s*[:=]\s*(\S+))",
                None,
            ),
            // 连接串内嵌凭据 (postgres://user:pass@host, mongodb://user:pass@, redis://:pass@)。
            // 组 1 = user:pass (机密), 协议 + @host 保留可见。
            (
                "conn_string",
                r"(?i)(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis|mysql|amqp|ftp|sftp)://[^/\s:@]+:([^@/\s]+)@",
                None,
            ),
            // 凭据键值模式 —— 带显式标签 (password=/secret=/KEY=val), 标签证明机密意图, 优先于裸数字。
            // password/passwd/pwd 键值 —— 组 1 = 值 (值可含数字, 须先于 id_number/credit_card 免被吞)。
            (
                "password",
                r#"(?i)(?:password|passwd|pwd)\s*["']?\s*[:=]\s*["']?([^\s"']+)"#,
                None,
            ),
            // secret/token 通用键值 (JSON/ENV/配置) —— 组 1 = 值。补 PRD §8 "敏感字段" 语义泛化。
            (
                "secret_kv",
                r#"(?i)(?:secret|token|access[_-]?token)["']?\s*[:=]\s*["']?([^\s"']{6,})"#,
                None,
            ),
            // .env 风格泛化 KEY=value (大写下划线键名 = 配置/凭据惯例) —— 组 1 = 值, 键名保留可见。
            ("env_kv", r"(?m)^[A-Z][A-Z0-9_]{2,}=(\S+)", None),
            // .netrc 风格 password XXX —— 组 1 = 值。
            ("netrc", r"(?i)password\s+(\S+)", None),
            // PII: email (issue #2) —— 放凭据模式之后: 连接串 user:pass@host 的 pass@host 会被 email 吞,
            //   故须让 conn_string 先吃 (先到先拒重叠)。非数字, 与下游 id_number/phone 无重叠。
            (
                "email",
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                None,
            ),
            // PII: ipv4 (issue #2) —— \b 词边界 + validator (每段 ≤255, 边界非数字/点)。
            (
                "ipv4",
                r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
                Some(valid_ipv4),
            ),
            // AWS Secret Access Key —— 40 字符 base64 集 (A-Za-z0-9/+=), 无 AKIA 前缀 (那是 access key id,
            // 已归 api_key)。validator 排除全同字符 (aaaa…) 防误报 + 边界校验 (regex crate 不支持
            // lookaround, 边界由 valid_aws_secret(content,s,e) 检查前后非 base64 字符)。
            ("aws_secret", r"[A-Za-z0-9/+=]{40}", Some(valid_aws_secret)),
            // 信用卡号 \d{13,19} —— validator Luhn 校验 + 边界 (regex crate 不支持 lookaround,
            // 边界由 valid_luhn(content,s,e) 检查前后非数字, 防吞 id_number/phone 子串)。
            ("credit_card", r"\d{13,19}", Some(valid_luhn)),
            // 手机号 (中国大陆 1[3-9]\d{9}) —— validator 边界校验 (前后非数字, 防吞入更长数字)。
            ("phone", r"1[3-9]\d{9}", Some(valid_phone)),
            // 身份证号 \d{17}[\dXx] —— 原 4 类保留。最后: 被前面凭据标签 + 边界数字模式先吃, 仅独立 17 位裸串落此。
            ("id_number", r"\d{17}[\dXx]", None),
        ];
        let mut patterns = Vec::with_capacity(defs.len());
        for (name, pat, validator) in defs {
            patterns.push(PatternDef {
                name,
                re: Regex::new(pat)?,
                validator,
            });
        }
        Ok(Self { patterns })
    }

    // P0-8: 按字符边界取末4字符, 非字节切片。原 s[n-4..] 在 CJK (3字节/字)/emoji (4字节)
    // 上 panic (byte index not char boundary) → redact_irreversible panic → worker 崩溃。
    fn last4(s: &str) -> String {
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        if n <= 4 {
            s.to_string()
        } else {
            chars[n - 4..].iter().collect()
        }
    }

    // C19: 组 1 (若有) = 敏感值, 其前为可见标签前缀 (password:/api_key=)。
    // 脱敏仅替换值, 保留前缀 (DLP 惯例: 字段名可见, 机密脱敏)。
    // 无组 1 (PEM 块/OpenSSH/JWK) → 前缀空, 值=全匹配。
    fn split_value(c: &regex::Captures) -> (String, String) {
        let full = c.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
        if full.is_empty() {
            return (String::new(), String::new());
        }
        match c.get(1) {
            Some(val_m) if !val_m.as_str().is_empty() => {
                let rel = val_m.start() - c.get(0).unwrap().start();
                let prefix = full[..rel].to_string();
                let value = val_m.as_str().to_string();
                (prefix, value)
            }
            _ => (String::new(), full),
        }
    }

    // L6 span 追踪核心: 在原内容上一次收集所有模式命中 (带字节偏移), 拒重叠 span,
    // 末到首单 pass 重建。原顺序 replace_all 在已脱敏文本上跑 —— id_number 匹配先前模式写入
    // 的 tok_<32hex> 占位符内 17 位数字子串 → 腐蚀原占位符 → extract_placeholders 找不到 →
    // reveal 撞 H6 → 可逆脱敏静默降级为不可逆。span 追踪消此 (占位符永不写回原内容, 单趟构建)。
    // accepted span 集合; 新命中与任一已接受 span 重叠即跳过 (首个模式优先, 防 id_number 吞 api_key)。
    fn collect_spans(&self, content: &str) -> Vec<AcceptedMatch> {
        let mut accepted: Vec<AcceptedMatch> = Vec::new();
        for pd in &self.patterns {
            let name_tag = pd.name;
            for c in pd.re.captures_iter(content) {
                let full = match c.get(0) {
                    Some(m) => m,
                    None => continue,
                };
                let (_prefix, value) = Self::split_value(&c);
                // 命中 span = 值 (组1) 区间; 无组1 → 全匹配区间。脱敏只替换值, 前缀保留原位。
                let (s, e) = match c.get(1) {
                    Some(vm) if !vm.as_str().is_empty() => (vm.start(), vm.end()),
                    _ => (full.start(), full.end()),
                };
                if s >= e {
                    continue;
                }
                // P1-1: validator (Luhn/字符多样性/数字边界) 拒假阳性候选。validator 接收
                // (content, span起, span止) —— 边界校验需 span 在原文中的前后字符 (regex 无 lookaround)。
                if let Some(check) = pd.validator {
                    if !check(content, s, e) {
                        continue;
                    }
                }
                // 拒重叠: 任一已接受 span 与 [s,e) 相交即跳过此命中。
                let overlaps = accepted.iter().any(|a| s < a.end && e > a.start);
                if overlaps {
                    continue;
                }
                accepted.push(AcceptedMatch {
                    start: s,
                    end: e,
                    name_tag,
                    value,
                });
            }
        }
        accepted
    }

    pub fn redact(&self, content: &str) -> String {
        let spans = self.collect_spans(content);
        if spans.is_empty() {
            return content.to_string();
        }
        // 末到首排序: 重建从高偏移起替换, 低偏移位置不受影响。
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            // span = group1 (值) 区间, 前缀 (group0..group1) 已在原位保留, 仅替换值。
            let repl = format!("[REDACTED:{}]", m.name_tag);
            out.replace_range(m.start..m.end, &repl);
        }
        out
    }

    // P2: redact 同时计命中数, evaluate 一次遍历取代 has_sensitive+redact 二扫。
    // 返 (脱敏后内容, 命中数); 命中数>0 → 有敏感内容。语义与 redact+has_sensitive 等价但单趟。
    pub fn redact_counted(&self, content: &str) -> (String, usize) {
        let spans = self.collect_spans(content);
        let total = spans.len();
        if spans.is_empty() {
            return (content.to_string(), 0);
        }
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            let repl = format!("[REDACTED:{}]", m.name_tag);
            out.replace_range(m.start..m.end, &repl);
        }
        (out, total)
    }

    pub fn redact_irreversible(&self, content: &str) -> String {
        let spans = self.collect_spans(content);
        if spans.is_empty() {
            return content.to_string();
        }
        let mut ordered = spans;
        ordered.sort_by_key(|m| Reverse(m.start));
        let mut out = content.to_string();
        for m in &ordered {
            let repl = format!("[REDACTED:{}#{}]", m.name_tag, Self::last4(&m.value));
            out.replace_range(m.start..m.end, &repl);
        }
        out
    }

    pub fn redact_reversible(&self, content: &str) -> (String, Vec<ReversibleMatch>) {
        let spans = self.collect_spans(content);
        if spans.is_empty() {
            return (content.to_string(), Vec::new());
        }
        // matches 按文本先后序 (caller 存首 token 为 token_map_id); 重建从高偏移起。
        let mut by_pos: Vec<&AcceptedMatch> = spans.iter().collect();
        by_pos.sort_by_key(|m| m.start);
        let mut matches = Vec::with_capacity(by_pos.len());
        for m in &by_pos {
            let token_id = format!("tok_{}", Uuid::new_v4().simple());
            let placeholder = format!("[REDACTED:{}#{}]", m.name_tag, token_id);
            matches.push(ReversibleMatch {
                placeholder: placeholder.clone(),
                token_id: token_id.clone(),
                original: m.value.clone(),
            });
        }
        // 重建需 span desc; 同时按 by_pos 下标取对应 token (保证 token↔span 正确绑定)。
        let mut idx_desc: Vec<usize> = (0..by_pos.len()).collect();
        idx_desc.sort_by_key(|&i| Reverse(by_pos[i].start));
        let mut out = content.to_string();
        for i in idx_desc {
            let m = by_pos[i];
            let repl = format!("[REDACTED:{}#{}]", m.name_tag, matches[i].token_id);
            out.replace_range(m.start..m.end, &repl);
        }
        (out, matches)
    }

    pub fn has_sensitive(&self, content: &str) -> bool {
        // 与 collect_spans 语义对齐: validator (Luhn/多样性/边界) 拒的候选不计为敏感。
        self.patterns.iter().any(|pd| {
            pd.re.captures_iter(content).any(|c| {
                let full = match c.get(0) {
                    Some(m) => m,
                    None => return false,
                };
                let (s, e) = match c.get(1) {
                    Some(vm) if !vm.as_str().is_empty() => (vm.start(), vm.end()),
                    _ => (full.start(), full.end()),
                };
                if s >= e {
                    return false;
                }
                match pd.validator {
                    Some(check) => check(content, s, e),
                    None => true,
                }
            })
        })
    }

    pub fn extract_placeholders(&self, content: &str) -> Vec<(String, String)> {
        // M4: OnceLock 缓存, 非每次 Regex::new().unwrap() (编译失败 panic + 重复编译开销)。
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"\[REDACTED:([a-z_]+)#(tok_[0-9a-f]+)\]")
                .expect("placeholder regex (static)")
        });
        re.captures_iter(content)
            .filter_map(|c| {
                let kind = c.get(1)?.as_str().to_string();
                let token_id = c.get(2)?.as_str().to_string();
                Some((kind, token_id))
            })
            .collect()
    }
}

// P1-1 (audit §1.10, 规则 5): 信用卡 Luhn 校验 + 数字边界 —— 正则只匹配长度 13-19 数字,
// validator (a) 检查 span 前后非数字 (regex 无 lookaround, 边界用代码), 防吞 id_number/phone
// 子段; (b) Luhn 算法确认是真实卡号非任意数字串 (降低假阳性: 13-19 位数字非支付语境频繁出现)。
fn valid_luhn(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && bytes[start - 1].is_ascii_digit() {
        return false;
    }
    if end < bytes.len() && bytes[end].is_ascii_digit() {
        return false;
    }
    let s = &content[start..end];
    let digits: Vec<u64> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| (c as u64) - 48)
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum: u64 = 0;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut x = if double { d * 2 } else { d };
        if x > 9 {
            x -= 9;
        }
        sum += x;
        double = !double;
    }
    sum.is_multiple_of(10)
}

// P1-1 (audit §1.10, 规则 5): AWS Secret Access Key 假阳性防御 —— 40 字符 base64 集。validator
// (a) span 前后非 base64 字符 (边界, 防 40 字符是更长串的子段); (b) 字符多样性 (≥6 distinct,
// 排除 "aaaa…"/"////…" 全同静态串, 真实密钥必有多样性)。
fn valid_aws_secret(content: &str, start: usize, end: usize) -> bool {
    let is_base64 = |b: u8| b.is_ascii_alphanumeric() || b == b'/' || b == b'+' || b == b'=';
    let bytes = content.as_bytes();
    if start > 0 && is_base64(bytes[start - 1]) {
        return false;
    }
    if end < bytes.len() && is_base64(bytes[end]) {
        return false;
    }
    let s = &content[start..end];
    if s.len() != 40 {
        return false;
    }
    let mut distinct = std::collections::HashSet::new();
    for b in s.bytes() {
        distinct.insert(b);
    }
    distinct.len() >= 6
}

// P1-1 (audit §1.10): 手机号边界校验 —— span 前后非数字, 防吞入 id_number 等更长数字子段。
fn valid_phone(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && bytes[start - 1].is_ascii_digit() {
        return false;
    }
    if end < bytes.len() && bytes[end].is_ascii_digit() {
        return false;
    }
    true
}

// issue #2: ipv4 每段 ≤ 255 (regex 只限 1-3 位, validator 拒 256+ 假阳性如 999.1.1.1)。
fn valid_ipv4(content: &str, start: usize, end: usize) -> bool {
    let bytes = content.as_bytes();
    if start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
        return false;
    }
    if end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
        return false;
    }
    content[start..end]
        .split('.')
        .all(|seg| seg.parse::<u8>().is_ok())
}

impl Default for Redactor {
    fn default() -> Self {
        // M4: new() 返 Result; Default 兜底 panic (静态模式编译应永不失败, 仅测试用)。
        Self::new().expect("redactor default: static regex compile failed")
    }
}
