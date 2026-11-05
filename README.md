# 🛡️ AgentShield

**AI Agent & MCP Security Assessment Toolkit** — static analysis for Model Context
Protocol (MCP) configurations. Point it at an MCP config and it flags secret exposure,
excessive agency, insecure transport, tool-poisoning indicators, and supply-chain risk —
then scores the overall risk and renders an HTML report.

> **100% static & offline.** AgentShield reads and parses the config; it never executes
> the config, launches a server, or makes a network call. Safe to run on any config you
> are authorized to review.

Built by Nitika Kumari (offensive security · AI/LLM & MCP security). Companion to my
[Agent Heist](https://github.com/nitikasec/agent-heist) lab and
[prompt-injection-harness](https://github.com/nitikasec/prompt-injection-harness).

## Why
MCP wires LLM agents to tools, files, and remote servers — a real, under-reviewed attack
surface (leaked keys in configs, `/`-mounted filesystems, plaintext endpoints, poisoned
tool descriptions). AgentShield gives a fast, explainable first pass over a config.

## Confirmed vs. indicator (important)
Every finding carries a **confidence** so you never over-claim:
- **confirmed** — definitely present (e.g. a literal provider API key, a `http://` endpoint).
- **indicator** — likely risky but needs human review (e.g. a tool description that *reads
  like* a prompt-injection payload). AgentShield does **not** claim to have verified these.

## Install
Python 3.9+. **No third-party dependencies** (standard library only — light on an 8 GB machine).
```bash
git clone <this repo> && cd agentshield
```

## Usage
```bash
# A) scan an MCP CONFIG (secrets, transport, agency, poisoning, supply-chain)
python -m agentshield scan samples/vulnerable_mcp_config.json --html report.html --json report.json

# scan your real Claude Desktop / Cursor config (read-only)
python -m agentshield scan ~/Library/Application\ Support/Claude/claude_desktop_config.json

# B) scan an MCP SERVER'S SOURCE CODE (the high-impact bug classes)
python -m agentshield scan-source ./path/to/mcp-server            # a directory
python -m agentshield scan-source samples/source/vulnerable_server.py   # a single file
```
Exit codes (handy in CI): `scan` is non-zero on any **confirmed** finding; `scan-source` is
non-zero on any **CRITICAL/HIGH** indicator.

## What it checks (MVP)
| Check | Category | Confidence |
|-------|----------|------------|
| Hardcoded provider API keys (Anthropic/OpenAI/AWS/GitHub/Google/Slack) | secret-exposure | confirmed |
| Secret-like values set literally in `env` | secret-exposure | indicator |
| Sensitive host vars passed to third-party servers | secret-exposure | indicator |
| Plaintext `http://` / `ws://` remote servers | insecure-transport | confirmed |
| Remote server with no visible auth | weak-auth | indicator |
| Shell-wrapped launch (`bash -c`) / dangerous flags / pipe-to-shell | excessive-agency | indicator |
| Filesystem server mounting `/`, `~`, or a home root | excessive-agency | indicator |
| Tool descriptions containing injection-style instructions | tool-poisoning | indicator |
| Unpinned auto-install (`npx -y` / `uvx`) | supply-chain | indicator |

Risk score (0–100) weights severity × confidence; indicators count at half weight.

## What it checks — SOURCE CODE (`scan-source`, new in v0.2)
Static review of an MCP server's source (`.py .js .ts .go …`) for the vulnerability classes that
actually ship in real MCP servers — codified from hand-auditing open-source servers. Source matches
are always **indicator** (static analysis can't prove the input is attacker-reachable); severity
reflects impact *if* exploitable.

| Check | Category | Severity |
|-------|----------|----------|
| OS command injection — shell string built from input (`exec`/`os.system`/interpolation) | command-injection | CRITICAL |
| `subprocess(..., shell=True)` / child process spawned with a shell | command-injection | HIGH |
| Prefix-match path check (`startswith`/`startsWith` with no separator boundary) → sandbox escape | path-traversal | HIGH |
| Server-side request to a non-constant URL (fetch/requests/axios) → SSRF | ssrf | HIGH |
| Token / credential passthrough (forwards an inbound `Authorization`) → confused deputy | token-passthrough | HIGH |
| Dynamic code evaluation (`eval` / `exec` / `new Function`) | code-injection | HIGH |

It won't flag the *correct* fix (e.g. an argv array, or a `startswith(root + os.sep)` boundary) —
keeping false positives low is a design goal.

## Tests
```bash
python -m unittest discover -s tests -v   # 33 offline tests (config + source)
```

## Limitations (scope honesty)
- **Static only** — it reads config structure; it cannot confirm runtime behaviour, nor
  prove a tool description is malicious (hence "indicator").
- Heuristic secret/injection detection — expect occasional false positives/negatives; treat
  indicators as leads for manual review, not verdicts.
- Covers the common `mcpServers` config shape; richer manifest formats are on the roadmap.

## Roadmap
- [x] **Source-code scanning** (`scan-source`): command injection, path/sandbox escape, SSRF,
      token passthrough, eval — codified from real MCP-server findings *(v0.2)*
- [ ] CI GitHub Action (fail the build on CRITICAL/HIGH) — the paid-tier hook
- [ ] Live (authorized) MCP server probing: enumerate tools, check input validation
- [ ] Canary-based prompt-injection test against a running agent (reuse prompt-injection-harness)
- [ ] More config formats + policy baselines + HTML report for source scans

## Ethics
Analyze only configs and servers you own or are explicitly authorized to assess. The sample
configs use **fake** values and exist for testing. MIT licensed.
