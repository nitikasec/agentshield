"""AgentShield — static security analyzer for MCP (Model Context Protocol) configs.

Analyzes an MCP client/server configuration (e.g. a Claude Desktop / Cursor style
`mcpServers` block, or a tool manifest) WITHOUT executing anything. It is 100% static
and offline — safe to run against any config you are authorized to review.

Design principle (important): every finding is labelled with a CONFIDENCE:
  - "confirmed" : the issue is definitely present (e.g. a literal API key matching a
                  known provider pattern, or a plaintext http:// endpoint).
  - "indicator" : something that is likely risky but needs human review (e.g. a tool
                  description that *reads like* a prompt-injection payload).
We never claim to have "detected a vulnerability" we cannot verify statically.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field, asdict


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 4, "INFO": 1}
CONFIDENCE_FACTOR = {"confirmed": 1.0, "indicator": 0.5}


@dataclass
class Finding:
    id: str
    title: str
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str       # confirmed | indicator
    category: str         # secret-exposure | excessive-agency | insecure-transport | tool-poisoning | supply-chain | weak-auth
    where: str            # JSON path / server name
    evidence: str         # short, redacted snippet
    recommendation: str

    def weight(self) -> float:
        return SEVERITY_WEIGHT.get(self.severity, 1) * CONFIDENCE_FACTOR.get(self.confidence, 0.5)


@dataclass
class Report:
    findings: list = field(default_factory=list)
    servers_analyzed: int = 0

    @property
    def risk_score(self) -> int:
        return int(min(100, round(sum(f.weight() for f in self.findings))))

    @property
    def rating(self) -> str:
        s = self.risk_score
        if s == 0:
            return "CLEAN"
        if s >= 70:
            return "CRITICAL"
        if s >= 40:
            return "HIGH"
        if s >= 15:
            return "MEDIUM"
        return "LOW"

    @property
    def confirmed(self):
        return [f for f in self.findings if f.confidence == "confirmed"]

    @property
    def indicators(self):
        return [f for f in self.findings if f.confidence == "indicator"]

    def to_dict(self):
        return {
            "risk_score": self.risk_score,
            "rating": self.rating,
            "servers_analyzed": self.servers_analyzed,
            "counts": {
                "confirmed": len(self.confirmed),
                "indicators": len(self.indicators),
                "total": len(self.findings),
            },
            "findings": [asdict(f) for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
# Known secret patterns -> a literal match is CONFIRMED secret exposure.
SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    # Tightened to real OpenAI key shapes (project keys, or legacy sk-+48) to avoid
    # false-positives on arbitrary "sk-..." strings (e.g. build hashes).
    ("OpenAI API key", re.compile(r"sk-(?:proj-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{48})")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
]
SECRETISH_KEY = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")
ENV_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$")   # ${VAR} or $VAR — the SAFE pattern

# Prompt-injection / tool-poisoning phrases -> INDICATOR in any description/string.
INJECTION_PHRASES = [
    "ignore previous", "ignore all previous", "disregard previous", "disregard all",
    "do not tell", "don't tell the user", "without telling", "without informing",
    "system prompt", "exfiltrat", "regardless of", "you must always", "you must never",
    "override your", "reveal the", "secret token", "send the contents", "base64 the",
]

# Dangerous launch commands / flags.
SHELLS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"}
DANGEROUS_SUBSTR = ["| sh", "| bash", "curl ", "wget ", "rm -rf", "--dangerously",
                    "--no-sandbox", "--yolo", "eval(", ";rm ", "&& rm "]
BROAD_FS_ROOTS = {"/", "~", "$HOME", "/users", "/home", "c:\\", "c:/"}
SENSITIVE_ENV = {"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "GH_TOKEN",
                 "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SSH_PRIVATE_KEY", "GCP_SA_KEY"}


def _redact(s: str, keep: int = 6) -> str:
    s = str(s)
    return s if len(s) <= keep else s[:keep] + "…[redacted]"


def _mask_url_creds(u) -> str:
    """Mask a user:password@ embedded in a URL so it never reaches any output."""
    return re.sub(r"(://[^/:@\s]+:)[^/@\s]+(@)", r"\1…[redacted]\2", str(u))


def _iter_strings(obj, path="$"):
    """Yield (json_path, string_value) for every string anywhere in the config."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_strings(v, f"{path}[{i}]")


def _servers(config: dict) -> dict:
    """Support common shapes: {mcpServers:{...}} (Claude/Cursor), {servers:{...}}, or a bare map."""
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(config.get(key), dict):
            return config[key]
    # bare map of name -> {command/url/...}
    if all(isinstance(v, dict) for v in config.values()) and config:
        return config
    return {}


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _check_secrets(config, findings):
    # 1) literal known-provider keys anywhere -> CONFIRMED
    for path, val in _iter_strings(config):
        for label, pat in SECRET_PATTERNS:
            m = pat.search(val)
            if m:
                findings.append(Finding(
                    id="AS-SECRET-001", title=f"Hardcoded {label} in MCP config",
                    severity="CRITICAL", confidence="confirmed", category="secret-exposure",
                    where=path, evidence=_redact(m.group(0)),
                    recommendation="Remove the literal secret; pass it via an environment "
                                   "variable reference (e.g. \"${API_KEY}\") and store the "
                                   "value outside the config. Rotate the exposed key.",
                ))
    # 2) a secret-named env/field with a literal (non-env-ref) value -> INDICATOR
    for name, server in _servers(config).items():
        env = server.get("env", {}) if isinstance(server, dict) else {}
        for k, v in (env.items() if isinstance(env, dict) else []):
            if isinstance(v, str) and SECRETISH_KEY.search(k) and v and not ENV_REF.match(v.strip()):
                # skip if already flagged as a known-pattern secret
                if not any(p.search(v) for _, p in SECRET_PATTERNS):
                    findings.append(Finding(
                        id="AS-SECRET-002",
                        title=f"Secret-like value set literally in env '{k}'",
                        severity="HIGH", confidence="indicator", category="secret-exposure",
                        where=f"mcpServers.{name}.env.{k}", evidence=_redact(v),
                        recommendation="Confirm whether this is a real secret. If so, use an "
                                       "env-var reference and keep the value out of the config.",
                    ))


def _check_servers(config, findings):
    for name, server in _servers(config).items():
        if not isinstance(server, dict):
            continue
        cmd = str(server.get("command", "")).lower()
        args = server.get("args", []) if isinstance(server.get("args"), list) else []
        args_s = " ".join(str(a) for a in args)
        url = server.get("url") or server.get("endpoint")

        # dangerous command / flags
        base = cmd.split("/")[-1]
        joined = (cmd + " " + args_s).lower()
        if base in SHELLS and ("-c" in args or "/c" in args):
            findings.append(Finding(
                id="AS-CMD-001", title=f"MCP server '{name}' launches a shell with -c",
                severity="HIGH", confidence="indicator", category="excessive-agency",
                where=f"mcpServers.{name}.command", evidence=_redact(joined, 40),
                recommendation="Avoid wrapping the server in a shell; run the binary directly. "
                               "Shell wrappers widen the attack surface and ease command injection.",
            ))
        for bad in DANGEROUS_SUBSTR:
            if bad in joined:
                findings.append(Finding(
                    id="AS-CMD-002", title=f"Dangerous command pattern in '{name}': '{bad.strip()}'",
                    severity="HIGH", confidence="indicator", category="excessive-agency",
                    where=f"mcpServers.{name}.args", evidence=_redact(joined, 60),
                    recommendation="Review this launch command; piping remote content into a shell "
                                   "or destructive flags are classic RCE/supply-chain risks.",
                ))
                break

        # over-broad filesystem scope
        looks_fs = "filesystem" in name.lower() or "filesystem" in joined or "server-filesystem" in joined
        if looks_fs:
            for a in args:
                if str(a).strip().lower().rstrip("/") in {r.rstrip("/") for r in BROAD_FS_ROOTS}:
                    findings.append(Finding(
                        id="AS-FS-001", title=f"Filesystem server '{name}' mounts a broad root",
                        severity="HIGH", confidence="indicator", category="excessive-agency",
                        where=f"mcpServers.{name}.args", evidence=_redact(str(a)),
                        recommendation="Scope the filesystem server to a specific project directory, "
                                       "never '/', '~' or a home root. Excessive agency = the model "
                                       "can read/modify anything the server can reach.",
                    ))

        # credentials embedded in the URL (user:password@host) -> confirmed secret exposure
        if isinstance(url, str):
            cred = re.search(r"://[^/:@\s]+:[^/@\s]+@", url)
            if cred:
                masked = re.sub(r"(://[^/:@\s]+:)[^/@\s]+(@)", r"\1…[redacted]\2", url)
                findings.append(Finding(
                    id="AS-SECRET-004", title=f"Credentials embedded in URL for server '{name}'",
                    severity="CRITICAL", confidence="confirmed", category="secret-exposure",
                    where=f"mcpServers.{name}.url", evidence=_redact(masked, 50),
                    recommendation="Remove inline user:password from the URL; pass credentials via an "
                                   "auth header/token sourced from an environment variable.",
                ))

        # insecure transport (remote server over plaintext)
        if isinstance(url, str) and (url.startswith("http://") or url.startswith("ws://")):
            findings.append(Finding(
                id="AS-NET-001", title=f"Remote MCP server '{name}' uses plaintext transport",
                severity="HIGH", confidence="confirmed", category="insecure-transport",
                where=f"mcpServers.{name}.url", evidence=_redact(_mask_url_creds(url), 30),
                recommendation="Use https:// / wss://. Plaintext MCP traffic can be read and "
                               "tampered with (tool results and arguments in the clear).",
            ))

        # remote server with no visible auth -> indicator
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            blob = str(server).lower()
            if not any(t in blob for t in ("authorization", "bearer", "token", "api_key", "apikey", "headers")):
                findings.append(Finding(
                    id="AS-AUTH-001", title=f"Remote MCP server '{name}' has no visible authentication",
                    severity="MEDIUM", confidence="indicator", category="weak-auth",
                    where=f"mcpServers.{name}", evidence=_redact(_mask_url_creds(url), 30),
                    recommendation="Confirm the endpoint requires authentication. An unauthenticated "
                                   "remote tool server can be called or spoofed by anyone.",
                ))

        # sensitive host env passed to a third-party server -> indicator
        env = server.get("env", {})
        if isinstance(env, dict):
            for k in env:
                if k.upper() in SENSITIVE_ENV:
                    findings.append(Finding(
                        id="AS-SECRET-003", title=f"Sensitive host variable '{k}' passed to server '{name}'",
                        severity="MEDIUM", confidence="indicator", category="secret-exposure",
                        where=f"mcpServers.{name}.env.{k}", evidence=k,
                        recommendation="Only pass credentials a server truly needs; a compromised or "
                                       "malicious third-party server inherits whatever you hand it.",
                    ))

        # unpinned auto-install (npx -y / uvx) -> supply-chain indicator
        if base in {"npx", "uvx"} and ("-y" in args or base == "uvx"):
            pkg = next((str(a) for a in args if not str(a).startswith("-")), "")
            if pkg and "@" not in pkg.split("/")[-1]:
                findings.append(Finding(
                    id="AS-SUPPLY-001", title=f"Server '{name}' auto-installs an unpinned package",
                    severity="LOW", confidence="indicator", category="supply-chain",
                    where=f"mcpServers.{name}.args", evidence=_redact(pkg, 40),
                    recommendation="Pin the package version (name@x.y.z) and prefer vetted publishers; "
                                   "'-y' auto-accepts installing whatever the registry serves.",
                ))


def _check_tool_poisoning(config, findings):
    for path, val in _iter_strings(config):
        low = val.lower()
        if len(val) < 15:
            continue
        hit = next((p for p in INJECTION_PHRASES if p in low), None)
        if hit:
            findings.append(Finding(
                id="AS-POISON-001", title="Possible tool-poisoning / injected instruction in text",
                severity="HIGH", confidence="indicator", category="tool-poisoning",
                where=path, evidence=f"…contains '{hit}': " + _redact(val, 60),
                recommendation="Review this tool description/string. Attacker-controlled tool "
                               "descriptions can carry instructions the model may follow "
                               "(tool poisoning / indirect prompt injection). Treat tool "
                               "metadata as untrusted input.",
            ))


def analyze(config) -> Report:
    """Run all static checks over a parsed MCP config and return a Report.

    Accepts any JSON-parsed value; a non-object (list/str/number/None) is reported
    as a malformed-input INFO finding rather than crashing.
    """
    findings: list = []
    if not isinstance(config, dict):
        findings.append(Finding(
            id="AS-INPUT-001", title="Config is not a JSON object",
            severity="INFO", confidence="indicator", category="input",
            where="$", evidence=f"top-level type: {type(config).__name__}",
            recommendation="Provide an MCP config as a JSON object, e.g. "
                           "{\"mcpServers\": { ... }}.",
        ))
        return Report(findings=findings, servers_analyzed=0)
    _check_secrets(config, findings)
    _check_servers(config, findings)
    _check_tool_poisoning(config, findings)
    # stable order: severity then confidence
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), 0 if f.confidence == "confirmed" else 1))
    return Report(findings=findings, servers_analyzed=len(_servers(config)))
