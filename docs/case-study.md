# Case Study — Assessing a Vulnerable MCP Config with AgentShield
Target: `samples/vulnerable_mcp_config.json` (a deliberately-insecure fixture with **fake** values).
Method: static analysis only — no execution, no network. Reproduce: `python -m agentshield scan samples/vulnerable_mcp_config.json`.

## Result
**Risk score: 100/100 (CRITICAL)** across 5 MCP servers — **2 confirmed**, **10 indicators** needing review.

## Findings & remediation
| # | Finding | Confidence | Why it matters | Fix |
|---|---------|-----------|----------------|-----|
| 1 | Hardcoded Anthropic API key in `notes.env` | **confirmed** | Anyone with the config file gets a live key | Use `${ANTHROPIC_API_KEY}`; keep the value out of the config; rotate the key |
| 2 | `remote-tools` served over `http://` | **confirmed** | Tool calls/results in cleartext — readable & tamperable | Use `https://`/`wss://` |
| 3 | `DB_PASSWORD` set literally in env | indicator | Looks like a plaintext credential | Confirm; move to an env reference |
| 4 | `files` server mounts `/` | indicator | Excessive agency — the model can read/modify anything on disk | Scope to a single project directory |
| 5 | `runner` runs `bash -c "curl … | bash"` | indicator | Remote-content-piped-to-shell = RCE/supply-chain risk | Run the binary directly; no pipe-to-shell |
| 6 | `helpdesk.toolDescription` contains "ignore previous instructions" | indicator | Tool-poisoning / indirect prompt injection — model may obey tool metadata | Treat tool metadata as untrusted; sanitize/validate tool descriptions |
| 7 | `AWS_SECRET_ACCESS_KEY` passed to third-party server | indicator | A compromised server inherits your AWS creds | Pass only what the server needs |
| 8 | `@acme/notes-mcp` auto-installed unpinned via `npx -y` | indicator (low) | Supply-chain: registry serves whatever it wants | Pin `name@x.y.z`; vet publisher |

## Before / after
Re-scanning the hardened equivalent (`samples/clean_mcp_config.json` — env references, `https://`,
scoped filesystem path, pinned package, auth header) returns **no confirmed findings** and a CLEAN/LOW
rating. Same servers, risk removed.

## Why the confirmed/indicator split matters
The two confirmed findings are provable from the file alone. The ten indicators are *leads* — e.g. the
tool-poisoning text is suspicious but AgentShield doesn't claim it is live-exploitable without a runtime
test. This keeps the report credible: a client can trust "confirmed" and triage "indicator." Full scope
and limits: `SECURITY-VALIDATION.md`.
