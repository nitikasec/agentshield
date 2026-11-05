"""AgentShield — static SOURCE-CODE scanner for MCP servers.

Where `analyzer.py` reviews an MCP *config*, this module reviews the *source code* of an
MCP server for the vulnerability classes that actually ship in the wild — the bug classes
found by hand-auditing real open-source MCP servers:

  - OS command injection      (shell string built from inputs)         -> CRITICAL
  - prefix-match path check    (sandbox escape via startswith/startsWith) -> HIGH
  - SSRF                       (server-side fetch of a non-constant URL)   -> HIGH
  - token / credential passthrough (forwarding an inbound Authorization)   -> HIGH
  - dynamic code evaluation    (eval / exec / new Function on input)        -> HIGH

Design principle (same as the config analyzer): we never over-claim. A static regex match
cannot prove the tainted value is attacker-reachable, so EVERY source finding is an
**indicator** — a high-signal lead for manual review, not a proven vulnerability. Severity
reflects the impact *if* exploitable; confidence stays honest.

100% static & offline: files are read and pattern-matched. Nothing is executed or imported.
"""
from __future__ import annotations

import os
import re

from .analyzer import Finding, Report

# Files we read; everything else is skipped.
SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".go"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env",
             "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages"}
MAX_FILE_BYTES = 1_500_000          # skip anything larger (generated/minified)
MAX_LINE_LEN = 400                  # skip minified / data lines

# Markers that a command string is built dynamically (not a constant).
_DYNAMIC = ("${", "f\"", "f'", ".format(", ") % ", " % ", " + ", "`", "%s", "%d")
_PATHWORDS = ("path", "dir", "root", "resolve", "realpath", "normpath", "abspath",
              "base", "allowed", "sandbox", "workdir", "working_dir")


def _trim(line: str, n: int = 140) -> str:
    line = line.strip()
    return line if len(line) <= n else line[:n] + "…"


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith("#") or s.startswith("//") or s.startswith("*") or s.startswith("/*")


def _has_dynamic(line: str) -> bool:
    return any(m in line for m in _DYNAMIC)


# --------------------------------------------------------------------------- #
# Per-line rules. Each returns a Finding (minus where/evidence) or None.
# --------------------------------------------------------------------------- #
_RE_JS_EXEC = re.compile(r"(?:child_process\.)?\bexec(?:Sync)?\s*\(")
_RE_PY_SYSTEM = re.compile(r"\bos\.(?:system|popen)\s*\(")
_RE_PY_SUBPROCESS = re.compile(r"\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\(")
_RE_SHELL_TRUE = re.compile(r"shell\s*[=:]\s*(?:True|true)")
_RE_PREFIX = re.compile(r"\.starts[wW]ith\s*\(")
_RE_SSRF = re.compile(
    r"(?:requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|request)"
    r"|urllib\.request\.urlopen|aiohttp\.[A-Za-z_]+|\bfetch|\baxios(?:\.(?:get|post|request))?"
    r"|\bgot)\s*\(\s*(?![\"'`]https?://)[A-Za-z_`$({]"
)
_RE_TOKEN_HDR = re.compile(r"(?i)authorization|bearer")
_RE_INBOUND = re.compile(r"(?i)req(?:uest)?\.headers|headers\.get\s*\(|headers\[|incoming|ctx\.request")
_RE_EVAL = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|(?<![A-Za-z_.])exec\s*\(")


def _scan_line(line: str):
    """Yield Finding templates (id,title,severity,category,recommendation) for a single line."""
    out = []
    low = line.lower()

    # 1) OS command injection -------------------------------------------------
    if _RE_JS_EXEC.search(line) and _has_dynamic(line):
        out.append(("AS-SRC-CMD-001", "Possible OS command injection (shell string built from input)",
                    "CRITICAL", "command-injection",
                    "A shell command is executed from a dynamically built string. Use an argv array "
                    "(execFile/spawn in Node, subprocess with a list and shell=False in Python) so "
                    "arguments cannot break out of the command."))
    elif _RE_PY_SYSTEM.search(line) and _has_dynamic(line):
        out.append(("AS-SRC-CMD-001", "Possible OS command injection via os.system/os.popen",
                    "CRITICAL", "command-injection",
                    "os.system/os.popen run through a shell. Build the command as a list and use "
                    "subprocess.run([...], shell=False); never interpolate inputs into a shell string."))
    elif _RE_PY_SUBPROCESS.search(line) and _RE_SHELL_TRUE.search(line):
        out.append(("AS-SRC-CMD-002", "subprocess call with shell=True",
                    "HIGH", "command-injection",
                    "shell=True runs the command through /bin/sh. Pass an argument list and shell=False; "
                    "if a shell is unavoidable, strictly validate/allowlist every interpolated value."))
    elif _RE_SHELL_TRUE.search(line) and ("spawn" in low or "exec" in low or "subprocess" in low):
        out.append(("AS-SRC-CMD-002", "Child process spawned with shell enabled",
                    "HIGH", "command-injection",
                    "Spawning with a shell widens the attack surface. Prefer an argv array with the "
                    "shell disabled so metacharacters in arguments are inert."))

    # 2) prefix-match path authorization (sandbox escape) --------------------
    # Skip the SAFE pattern: a separator boundary (root + os.sep / + '/') or commonpath.
    _safe_boundary = ("os.sep" in line or "path.sep" in line or "+ '/'" in line
                      or '+ "/"' in line or "+'/'" in line or '+"/"' in line
                      or "commonpath" in low or "commonprefix" in low)
    if _RE_PREFIX.search(line) and any(w in low for w in _PATHWORDS) and not _safe_boundary:
        out.append(("AS-SRC-PATH-001", "Path check uses prefix match (possible sandbox escape)",
                    "HIGH", "path-traversal",
                    "startswith/startsWith on a path has no separator boundary: an allowed root "
                    "'/srv/data' also matches '/srv/data-secrets'. Resolve to a real path and compare "
                    "with a trailing separator (or use commonpath / path.relative + '..' checks)."))

    # 3) SSRF — server-side fetch of a non-constant URL ----------------------
    if _RE_SSRF.search(line):
        out.append(("AS-SRC-SSRF-001", "Server-side request to a non-constant URL (possible SSRF)",
                    "HIGH", "ssrf",
                    "A fetch/HTTP call targets a variable URL. If the URL is influenced by input, an "
                    "attacker can reach internal services or cloud metadata (169.254.169.254). "
                    "Allowlist hosts/schemes and block private/link-local ranges after DNS resolution."))

    # 4) token / credential passthrough (confused deputy) --------------------
    if _RE_TOKEN_HDR.search(line) and _RE_INBOUND.search(line):
        out.append(("AS-SRC-TOKEN-001", "Possible token passthrough / confused-deputy",
                    "HIGH", "token-passthrough",
                    "An inbound Authorization/token appears to be forwarded onward. An MCP server should "
                    "not relay tokens that were not issued for it; validate the audience and mint/scope "
                    "its own credentials for downstream calls."))

    # 5) dynamic code evaluation (high-signal sink; flag whenever present) ----
    if _RE_EVAL.search(line):
        out.append(("AS-SRC-EVAL-001", "Dynamic code evaluation (eval/exec/new Function)",
                    "HIGH", "code-injection",
                    "Evaluating a dynamically built string can execute attacker input. Remove eval/exec/"
                    "new Function, or parse the input with a safe, explicit parser instead."))
    return out


def scan_text(text: str, where: str, findings: list) -> None:
    for i, raw in enumerate(text.splitlines(), start=1):
        if len(raw) > MAX_LINE_LEN or _is_comment(raw):
            continue
        for fid, title, sev, cat, rec in _scan_line(raw):
            findings.append(Finding(
                id=fid, title=title, severity=sev, confidence="indicator",
                category=cat, where=f"{where}:{i}", evidence=_trim(raw),
                recommendation=rec,
            ))


def scan_source(root: str) -> tuple:
    """Scan a file or directory tree of MCP-server source. Returns (Report, files_scanned)."""
    findings: list = []
    files = 0
    paths = []
    if os.path.isfile(root):
        paths = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() in SOURCE_EXTS:
                    paths.append(os.path.join(dirpath, fn))
    for p in paths:
        try:
            if os.path.getsize(p) > MAX_FILE_BYTES:
                continue
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        files += 1
        rel = os.path.relpath(p, root) if os.path.isdir(root) else os.path.basename(p)
        scan_text(text, rel, findings)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.where))
    rep = Report(findings=findings, servers_analyzed=files)
    return rep, files
