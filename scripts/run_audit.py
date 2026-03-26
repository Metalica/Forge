#!/usr/bin/env python3
import argparse
import json
import os
import re
from pathlib import Path

DEFAULT_EXCLUDES = {
    '.git',
    'node_modules',
    'dist',
    'build',
    'target',
    '.venv',
    'venv',
    '__pycache__',
    '.next',
    '.turbo',
    '.tmp',
    'artifacts',
    'runtimes',
    'models',
    'lamma.cpp',
}

EXCLUDED_FILENAMES = {
    'security_findings.json',
    'security_findings.md',
    'audit-findings.json',
    'audit-findings.md',
}

PATTERNS = [
    # agent / codex / prompt surfaces
    ("agent_instruction_files", r"AGENTS\.override\.md|AGENTS\.md|SKILL\.md", "Repo-controlled agent instructions"),
    ("agent_config", r"\.codex|\.agents|approval_policy|sandbox_mode|network_access|web_search|openai_base_url|model_provider|env_http_headers|http_headers", "Agent configuration and remote-provider surface"),
    ("mcp_surface", r"\bMCP\b|model context protocol|mcp[_-]server|mcpServers|notifications/tools/list_changed|oauth|redirect_uri", "MCP / connector / OAuth surface"),
    # execution sinks
    ("shell_exec", r"\b(exec|execvp|execl|spawn|popen|system)\b|bash -lc|zsh -lc|subprocess\.(Popen|run|call)|os\.system|child_process|ProcessBuilder|Runtime\.getRuntime", "Shell / process execution sink"),
    ("dynamic_eval", r"\beval\(|new Function\(|vm\.runIn|pickle\.loads|yaml\.load\(|marshal\.loads|exec\(", "Dynamic evaluation / unsafe deserialization"),
    # network / SSRF / proxy
    ("networking", r"fetch\(|axios|requests\.|httpx\.|reqwest|urllib|curl |wget |web_search|network_access|\bbase_url\b|\bproxy\b", "Networking / SSRF / provider proxy surface"),
    # file/path/temp
    ("path_handling", r"\b(realpath|normalize|resolve|join|canonicalize|abspath|relpath)\b|\.\./|tempfile|mktemp|/tmp|TMPDIR", "Path traversal / temp-file / canonicalization surface"),
    # secrets / telemetry
    ("secrets", r"OPENAI_API_KEY|API_KEY|AUTH_TOKEN|ACCESS_TOKEN|SECRET_KEY|PASSWORD|auth\.json|history\.jsonl|Authorization|Bearer\s+[A-Za-z0-9._-]+", "Secret material or credential storage"),
    ("telemetry", r"otel|telemetry|trace|tracing|log_user_prompt|tool_result|exporter|history\.persistence|analytics\.enabled", "Telemetry / logging / trace exposure"),
    # CI
    ("github_actions", r"pull_request_target|workflow_dispatch|issue_comment|pull_request|allow-users|drop-sudo|sudo|permissions:|secrets\.|\$\{\{", "CI/CD privilege and shell-injection surface"),
]

TEXT_EXTS = {
    '.py', '.js', '.ts', '.tsx', '.jsx', '.rs', '.go', '.java', '.kt', '.c', '.cc', '.cpp', '.h', '.hpp',
    '.cs', '.php', '.rb', '.swift', '.scala', '.lua', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.toml',
    '.json', '.jsonc', '.yaml', '.yml', '.xml', '.ini', '.cfg', '.conf', '.md', '.txt', '.sql', '.env',
    '.gradle', '.properties'
}


def is_text_candidate(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    name = path.name.lower()
    return name in {"dockerfile", "makefile", "jenkinsfile", "agents.md", "agents.override.md", "skill.md"}


def walk_files(root: Path):
    for base, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d not in DEFAULT_EXCLUDES and not d.lower().startswith('target')
        ]
        for f in files:
            p = Path(base) / f
            if f.lower() in EXCLUDED_FILENAMES:
                continue
            if is_text_candidate(p):
                yield p


def scan_file(path: Path):
    hits = []
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return hits
    lines = text.splitlines()
    for rule_id, pattern, desc in PATTERNS:
        rx = re.compile(pattern, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                hits.append({
                    "rule_id": rule_id,
                    "description": desc,
                    "path": str(path),
                    "line": i,
                    "snippet": line[:300],
                })
    return hits


def summarize(hits):
    by_rule = {}
    for h in hits:
        by_rule.setdefault(h['rule_id'], 0)
        by_rule[h['rule_id']] += 1
    return by_rule


def build_markdown(hits, summary, root: str) -> str:
    lines = []
    lines.append("# Security Audit Fast Scan")
    lines.append("")
    lines.append(f"Scanned root: `{root}`")
    lines.append("")
    lines.append("## Summary by rule")
    lines.append("")
    for rule, count in sorted(summary.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- `{rule}`: {count}")
    lines.append("")
    lines.append("## Raw hits")
    lines.append("")
    for h in hits:
        lines.append(f"- **{h['rule_id']}** `{h['path']}:{h['line']}` - {h['description']}")
        lines.append(f"  - `{h['snippet']}`")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("This is a triage scan, not proof of exploitability. Follow-up manual review is required.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Fast security triage scan for repos and agent systems.")
    ap.add_argument("--root", default=".")
    ap.add_argument("--json-out", default="audit-findings.json")
    ap.add_argument("--md-out", default="audit-findings.md")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    hits = []
    for p in walk_files(root):
        hits.extend(scan_file(p))

    summary = summarize(hits)
    payload = {
        "root": str(root),
        "summary": summary,
        "hits": hits,
    }
    Path(args.json_out).write_text(json.dumps(payload, indent=2), encoding='utf-8')
    Path(args.md_out).write_text(build_markdown(hits, summary, str(root)), encoding='utf-8')
    print(f"Wrote {args.json_out} and {args.md_out} with {len(hits)} hits.")


if __name__ == "__main__":
    main()
