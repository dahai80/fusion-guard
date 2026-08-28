// Stage 3 语义分析 (PRD §7.4 R5) — tree-sitter 多 grammar 代码内容扫描
//
// 仅在 feature = "semantic" 启用 (MVP 默认关, PRD §7.4 "需时再引且锁版本")。
// 命令类鉴权已由 Stage 2 shell-words 覆盖; 本阶段扫代码内容 (非命令), 检危险调用:
//   Python: os.system / subprocess.* / eval / exec / __import__ / pickle.loads
//   JS/TS:  eval / Function / child_process / fetch 外泄
//   Rust:   Command::new / std::process::Command / unsafe / fs::remove_dir_all
// 版本锁与 fusion-executor workspace 一致 (tree-sitter 0.25, grammars 0.23), 防 grammar 漂移。

#![cfg(feature = "semantic")]

use fg_core::{CheckStage, RiskLevel};
use tree_sitter::{Node, Parser};

use crate::tokenizer::TokenHit;

// ── 危险调用表 (per-language) ─────────────────────────────────────────
// 函数名前缀匹配 (语义扫描按调用表达式 callee 名命中)
//
// A9 SSOT: 这些表是语义阶段的唯一真相源。原 semantic_default_rules() 产出 6 条
// stage=Semantic GuardRule 注入规则集 (持久 SQLite), 但 evaluate 跳过非 Regex stage,
// 从不编译从不匹配 —— 死代码。两真相源解耦: admin 删 "semantic:py:os.system" 规则期望
// 禁用 os.system 检测, 实际语义扫描仍经 PY_DANGER_L4 命中, 违 Checkpoint 2 SSOT。
// 修 (b): 删 semantic_default_rules, 本表为语义执行权威, 非 admin 可变 (文档化)。
// 调用方经 guard.rule.list 仅见 Regex 规则, 语义检测能力固定。

const PY_DANGER_L4: &[&str] = &[
    "os.system",
    "os.popen",
    "os.exec",
    "os.execv",
    "os.execvp",
    "os.execve",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "commands.getoutput",
    "popen2.popen2",
];

const PY_DANGER_L3: &[&str] = &[
    "eval",
    "exec",
    "compile",
    "__import__",
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "shelve.open",
    "ctypes.CDLL",
    "ctypes.cdll.LoadLibrary",
];

const JS_DANGER_L4: &[&str] = &[
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
];

const JS_DANGER_L3: &[&str] = &["eval", "Function", "setTimeout", "setInterval"];

const RS_DANGER_L4: &[&str] = &["Command::new", "remove_dir_all", "remove_file"];

const RS_DANGER_L3: &[&str] = &["unsafe"];

#[derive(Debug, Clone)]
pub struct SemanticHit {
    pub language: &'static str,
    pub callee: String,
    pub risk: RiskLevel,
    pub reason: String,
    pub stage: CheckStage,
}

impl SemanticHit {
    pub fn to_token_hit(&self) -> TokenHit {
        TokenHit {
            binary: format!("semantic:{}:{}", self.language, self.callee),
            reason: self.reason.clone(),
            stage: CheckStage::Semantic,
            sensitive_target: self.risk == RiskLevel::L4,
        }
    }
}

// ── 入口: 多 grammar 尝试 ────────────────────────────────────────────
// C4: 不因 has_error 短路清零真实命中 (tree-sitter 错误恢复解析器, 危险节点仍在树中)。
// C5 引入跨语言裸命中风险 (eval/exec/compile 在 Python+JS 都触发): `const x=eval('1')`
// 在 Python grammar 下也命中 eval, 但 Python grammar 报错 (const 非法)。
// 决策: 优先采信"无解析错误"的 grammar 命中 (源语言确证); 若全 grammar 都有错, 才采信首个
// 非空命中 (C4 — 有错仍有真实危险调用如 os.system("rm -rf /") 中注入语法错)。
// 全部零命中 + 全部报错 → 追加 L2 parse-error (不静默 clean); 否则 clean。

pub fn semantic_check(content: &str) -> Vec<SemanticHit> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let candidates = [
        scan_python(trimmed),
        scan_javascript(trimmed),
        scan_typescript(trimmed),
        scan_rust(trimmed),
    ];
    // 1. 优先: 无错 grammar 的非空命中 (源语言确证, 跨语言裸命中不混淆)。
    for (hits, had_error) in &candidates {
        if !hits.is_empty() && !had_error {
            return hits.clone();
        }
    }
    // 2. 兜底: 全 grammar 有错时, 首个非空命中 (C4 — 有错源仍检真实危险调用)。
    for (hits, _had_error) in &candidates {
        if !hits.is_empty() {
            return hits.clone();
        }
    }
    // 3. 全部零命中。仅当所有 grammar 都报错 → 标注扫描可能不完整 (C4 不静默 clean)。
    // 任一 grammar 无错解析 (如 clean Rust) → 信任其零命中, 不误报。
    if candidates.iter().all(|(_, err)| *err) {
        vec![SemanticHit {
            language: "unknown",
            callee: "<parse-error>".into(),
            risk: RiskLevel::L2,
            reason: "源含解析错误, 语义扫描可能不完整 (C4)".into(),
            stage: CheckStage::Semantic,
        }]
    } else {
        Vec::new()
    }
}

// ── Python ───────────────────────────────────────────────────────────

// scan_* 返回 (危险命中, had_error)。had_error 仅作 grammar 回退决策, 不在此追加 L2。
// L2 parse-error hit 由 semantic_check 统一在"全 grammar 零命中且全报错"时追加。

fn scan_python(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: 不因 root has_error 短路。tree-sitter 是错误恢复解析器, 危险调用节点仍在树中
    // 可遍历。注入一个语法错误不应让 os.system("rm -rf /") 整文件静默 clean。
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    // C5: Python 专用遍历 —— 收集 import/别名绑定, 用别名解析 callee, 检危险 import +
    // 动态调度 (getattr/__import__/globals/locals/vars)。非 Python 语言仍走通用 walk_calls。
    walk_python(code, tree.root_node(), &mut hits);
    (hits, had_error)
}

// ── JavaScript ───────────────────────────────────────────────────────

fn scan_javascript(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: 不因 root has_error 短路 (见 scan_python 注释)。
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    walk_calls(
        code,
        tree.root_node(),
        "javascript",
        JS_DANGER_L4,
        JS_DANGER_L3,
        &mut hits,
    );
    (hits, had_error)
}

// ── TypeScript ───────────────────────────────────────────────────────

fn scan_typescript(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: 不因 root has_error 短路 (见 scan_python 注释)。
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    walk_calls(
        code,
        tree.root_node(),
        "typescript",
        JS_DANGER_L4,
        JS_DANGER_L3,
        &mut hits,
    );
    (hits, had_error)
}

// ── Rust ─────────────────────────────────────────────────────────────

fn scan_rust(code: &str) -> (Vec<SemanticHit>, bool) {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .is_err()
    {
        return (Vec::new(), true);
    }
    let tree = match parser.parse(code, None) {
        Some(t) => t,
        None => return (Vec::new(), true),
    };
    // C4: 不因 root has_error 短路 (见 scan_python 注释)。
    let had_error = tree.root_node().has_error();
    let mut hits = Vec::new();
    walk_calls(
        code,
        tree.root_node(),
        "rust",
        RS_DANGER_L4,
        RS_DANGER_L3,
        &mut hits,
    );
    (hits, had_error)
}

// ── C5: Python 专用遍历 (import/别名/动态调度) ──────────────────────────
// 三类命中:
//  1. 危险模块 import 本身 (os/subprocess/ctypes/pickle/marshal) → L3。无论后续是否调用,
//     导入危险模块即标注 (可执行 RCE 前置)。
//  2. from <危险模块> import Y → L3 (Y 多为 system/Popen/CDLL 等危险符号)。
//  3. call_expression: 用别名绑定解析 callee (import os as o → o.system→os.system);
//     动态调度 getattr/__import__/globals/locals/vars → L3 (无法证明安全)。
// 别名绑定表: alias 名 → 真实模块路径 (如 "o"→"os", "s"→"os.system")。
const PY_DANGER_MODULES: &[&str] = &[
    "os",
    "subprocess",
    "ctypes",
    "pickle",
    "marshal",
    "commands",
    "popen2",
];
const PY_DYNAMIC_DISPATCH: &[&str] = &[
    "getattr",
    "__import__",
    "globals",
    "locals",
    "vars",
    "eval",
    "exec",
    "compile",
];

fn walk_python(code: &str, root: Node, out: &mut Vec<SemanticHit>) {
    let mut aliases: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    walk_python_node(code, root, &mut aliases, out);
}

fn walk_python_node(
    code: &str,
    node: Node,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    let kind = node.kind();

    // import 语句: import os / import os as o / import os.path as p
    if kind == "import_statement" {
        collect_import_statement(code, node, aliases, out);
    }
    // from X import Y / from X import Y as s
    if kind == "import_from_statement" {
        collect_import_from(code, node, aliases, out);
    }

    // call: 别名解析 + 动态调度检测。tree-sitter-python 调用节点 kind = "call" (非 call_expression)。
    if kind == "call" || kind == "call_expression" {
        if let Some(callee_node) = node.child_by_field_name("function") {
            let callee = callee_node
                .utf8_text(code.as_bytes())
                .unwrap_or("")
                .trim()
                .to_string();
            if !callee.is_empty() {
                classify_python(&callee, aliases, out);
            }
        }
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            walk_python_node(code, cursor.node(), aliases, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// import os → alias "os"→"os", 危险模块即 L3 hit。
// import os as o → alias "o"→"os"。
// import os.path → alias "os"→"os" (顶层模块)。import os.path as p → "p"→"os.path"。
fn collect_import_statement(
    code: &str,
    node: Node,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    // tree-sitter-python: import_statement 下含 dotted_name + 可选 aliased_import。
    // 简健做法: 取整段源文本, 解析 "import X[.Y][ as A]" 与逗号多目标。
    let text = node.utf8_text(code.as_bytes()).unwrap_or("");
    parse_import_text(text, aliases, out, false);
}

// from os import system → alias "system"→"os.system"; X 危险 → L3。
// from os import system as s → "s"→"os.system"。
fn collect_import_from(
    code: &str,
    node: Node,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    let text = node.utf8_text(code.as_bytes()).unwrap_or("");
    parse_import_text(text, aliases, out, true);
}

// 文本级解析 import 语句 (tree-sitter field 跨 grammar 版本不稳, 文本解析更健)。
// is_from=true → from X import Y[, Z] 形式。
fn parse_import_text(
    text: &str,
    aliases: &mut std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
    is_from: bool,
) {
    let text = text.trim();
    if is_from {
        // from <module> import <names>
        let after_from = text.strip_prefix("from").unwrap_or(text).trim();
        let parts: Vec<&str> = after_from.splitn(2, "import").collect();
        if parts.len() != 2 {
            return;
        }
        let module = parts[0].trim();
        let names = parts[1].trim();
        if PY_DANGER_MODULES.contains(&module) {
            out.push(SemanticHit {
                language: "python",
                callee: format!("from {module} import"),
                risk: RiskLevel::L3,
                reason: format!("python 从危险模块 {} 导入 (C5)", module),
                stage: CheckStage::Semantic,
            });
        }
        // 每个 Y [as A] → alias
        for item in names.split(',') {
            let item = item.trim();
            let segs: Vec<&str> = item.split_whitespace().collect();
            if segs.is_empty() {
                continue;
            }
            let imported = segs[0];
            let bind_name = if segs.len() >= 3 && segs[1] == "as" {
                segs[2]
            } else {
                imported
            };
            let real = if imported == "*" {
                String::new()
            } else {
                format!("{module}.{imported}")
            };
            if !bind_name.is_empty() && !real.is_empty() {
                aliases.insert(bind_name.to_string(), real);
            }
        }
    } else {
        // import X[.Y][ as A][, X2[.Y2][ as A2]]
        let after_import = text.strip_prefix("import").unwrap_or(text).trim();
        for item in after_import.split(',') {
            let item = item.trim();
            let segs: Vec<&str> = item.split_whitespace().collect();
            if segs.is_empty() {
                continue;
            }
            let dotted = segs[0];
            let top = dotted.split('.').next().unwrap_or(dotted);
            let bind_name = if segs.len() >= 3 && segs[1] == "as" {
                segs[2]
            } else {
                top
            };
            if PY_DANGER_MODULES.contains(&top) {
                out.push(SemanticHit {
                    language: "python",
                    callee: format!("import {dotted}"),
                    risk: RiskLevel::L3,
                    reason: format!("python 导入危险模块 {} (C5)", top),
                    stage: CheckStage::Semantic,
                });
            }
            if !bind_name.is_empty() {
                aliases.insert(bind_name.to_string(), dotted.to_string());
            }
        }
    }
}

// Python callee 分类: 先别名解析 (o.system → os.system), 再查危险表 + 动态调度。
fn classify_python(
    callee: &str,
    aliases: &std::collections::HashMap<String, String>,
    out: &mut Vec<SemanticHit>,
) {
    // 动态调度: getattr/__import__/globals/locals/vars → L3 (无法证明安全)。
    // 同时 eval/exec/compile 本就是 PY_DANGER_L3, 这里显式标 reason。
    if PY_DYNAMIC_DISPATCH.contains(&callee) {
        out.push(SemanticHit {
            language: "python",
            callee: callee.to_string(),
            risk: RiskLevel::L3,
            reason: format!("python 动态调度/反射调用 (C5): {}", callee),
            stage: CheckStage::Semantic,
        });
        return;
    }
    // 别名解析: 取 callee 第一段 (点前) 查 alias, 重写为真实路径。
    let resolved = resolve_alias(callee, aliases);
    if danger_match(&resolved, PY_DANGER_L4) {
        out.push(SemanticHit {
            language: "python",
            callee: resolved.clone(),
            risk: RiskLevel::L4,
            reason: format!("python 危险调用 (L4, 别名解析): {}", resolved),
            stage: CheckStage::Semantic,
        });
        return;
    }
    if danger_match(&resolved, PY_DANGER_L3) {
        out.push(SemanticHit {
            language: "python",
            callee: resolved.clone(),
            risk: RiskLevel::L3,
            reason: format!("python 危险调用 (L3, 别名解析): {}", resolved),
            stage: CheckStage::Semantic,
        });
    }
}

// callee "o.system" → alias "o"→"os" → "os.system"。
// alias 表存顶层模块名, callee 第一段查表替换。
fn resolve_alias(callee: &str, aliases: &std::collections::HashMap<String, String>) -> String {
    let first = callee.split('.').next().unwrap_or(callee);
    if let Some(real) = aliases.get(first) {
        if first == callee {
            return real.clone();
        }
        let rest = &callee[first.len()..];
        return format!("{real}{rest}");
    }
    callee.to_string()
}

fn danger_match(callee: &str, table: &[&str]) -> bool {
    table.contains(&callee)
}

// ── 通用调用表达式遍历 ────────────────────────────────────────────────
// tree-sitter 各 grammar 的 call node kind: call_expression (py/js/ts),
// rust 的 call_expression (method/call). callee 文本取调用目标源码片段。
fn walk_calls(
    code: &str,
    node: Node,
    lang: &'static str,
    danger_l4: &[&str],
    danger_l3: &[&str],
    out: &mut Vec<SemanticHit>,
) {
    let mut cursor = node.walk();
    recurse_walk(&mut cursor, code, lang, danger_l4, danger_l3, out);
}

fn recurse_walk(
    cursor: &mut tree_sitter::TreeCursor,
    code: &str,
    lang: &'static str,
    danger_l4: &[&str],
    danger_l3: &[&str],
    out: &mut Vec<SemanticHit>,
) {
    loop {
        let node = cursor.node();
        let kind = node.kind();
        if kind == "call_expression" || kind == "call" {
            if let Some(callee_node) = node.child_by_field_name("function").or_else(|| {
                // rust grammar 无 function field, 取首非标点子节点
                node.named_child(0)
            }) {
                let callee = callee_node
                    .utf8_text(code.as_bytes())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !callee.is_empty() {
                    if let Some(h) = classify(&callee, lang, danger_l4, danger_l3) {
                        out.push(h);
                    }
                }
            }
        }

        if cursor.goto_first_child() {
            recurse_walk(cursor, code, lang, danger_l4, danger_l3, out);
            cursor.goto_parent();
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

fn classify(
    callee: &str,
    lang: &'static str,
    danger_l4: &[&str],
    danger_l3: &[&str],
) -> Option<SemanticHit> {
    // C5: 删 ends_with(":{d}") 死逻辑 — 匹配 foo:os.system 这类非法 Python 属性,
    // 永不命中真实代码, 仅增噪音。改为精确全等。
    if danger_l4.contains(&callee) {
        return Some(SemanticHit {
            language: lang,
            callee: callee.to_string(),
            risk: RiskLevel::L4,
            reason: format!("{} 危险调用 (L4): {}", lang, callee),
            stage: CheckStage::Semantic,
        });
    }
    if danger_l3.contains(&callee) {
        return Some(SemanticHit {
            language: lang,
            callee: callee.to_string(),
            risk: RiskLevel::L3,
            reason: format!("{} 危险调用 (L3): {}", lang, callee),
            stage: CheckStage::Semantic,
        });
    }
    None
}
