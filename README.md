# 🛡️ AgentShield

**AI Agent & MCP Security Assessment Toolkit** — static analysis for Model Context
Protocol (MCP) configurations. Point it at an MCP config and it flags secret exposure,
excessive agency, insecure transport, tool-poisoning indicators, and supply-chain risk —
then scores the overall risk and renders an HTML report.

> **100% static & offline.** AgentShield reads and parses the config; it never executes
> the config, launches a server, or makes a network call. Safe to run on any config you
> are authorized to review.

Built by Nitika Kumari (offensive security · AI/LLM & MCP security). Companion to my
[damn-vulnerable-mcp](https://github.com/nitikasec/damn-vulnerable-mcp) lab and
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
# scan a config, print a report, write HTML + JSON
python -m agentshield scan samples/vulnerable_mcp_config.json --html report.html --json report.json

# scan your real Claude Desktop / Cursor config (read-only)
python -m agentshield scan ~/Library/Application\ Support/Claude/claude_desktop_config.json
```
Exit code is non-zero if any **confirmed** finding is present (handy in CI).

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

## Tests
```bash
python -m unittest discover -s tests -v   # 12 offline tests
```

## Limitations (scope honesty)
- **Static only** — it reads config structure; it cannot confirm runtime behaviour, nor
  prove a tool description is malicious (hence "indicator").
- Heuristic secret/injection detection — expect occasional false positives/negatives; treat
  indicators as leads for manual review, not verdicts.
- Covers the common `mcpServers` config shape; richer manifest formats are on the roadmap.

## Roadmap
- [ ] Live (authorized) MCP server probing: enumerate tools, check input validation
- [ ] Canary-based prompt-injection test against a running agent (reuse prompt-injection-harness)
- [ ] More config formats + policy baselines
- [ ] CI GitHub Action

## Ethics
Analyze only configs and servers you own or are explicitly authorized to assess. The sample
configs use **fake** values and exist for testing. MIT licensed.
