# AgentShield — Commercial Packaging (draft)
Status: internal planning draft. Nothing deployed. Do not publish/buy infra without approval.

## Screenshots (ready to capture)
Open these in Chrome and screenshot for the landing page / demo:
- `docs/sample-report.html` — vulnerable config, **100/100 CRITICAL**, confirmed + indicator findings (the money shot)
- `docs/sample-report-clean.html` — hardened config, no confirmed issues (the "after")
Also screenshot the terminal: `python -m agentshield scan samples/vulnerable_mcp_config.json`.

## 2-minute demo script
**(0:00–0:15) Hook.** "MCP connects AI agents to tools, files and remote servers. Most teams never
security-review the config — where leaked keys, `/`-mounted filesystems, plaintext endpoints and
poisoned tool descriptions hide. AgentShield scans that config in seconds."
**(0:15–0:40) The problem.** Show `samples/vulnerable_mcp_config.json` — point at the hardcoded key,
the `http://` server, the filesystem root `/`, the tool description saying "ignore previous instructions."
**(0:40–1:20) Run it.** `python -m agentshield scan samples/vulnerable_mcp_config.json --html report.html`
— show the terminal findings, then open the HTML report: risk score 100/100, **confirmed** (hardcoded
key, plaintext transport) vs **indicator** (needs review) badges, and the secret **redacted** in output.
"It never runs the config — pure static analysis — and it never over-claims: indicators are flagged for
review, not asserted as proven."
**(1:20–1:45) Fix + rescan.** Switch to `clean_mcp_config.json` (env refs, https, scoped paths) — rescan
→ no confirmed issues. "Here's the before and after."
**(1:45–2:00) Close.** "AgentShield: a fast, honest first pass on AI-agent and MCP security. Open-source
core; Pro adds CI, live probing and policy baselines. Link below."

## Landing page draft (copy)
**Hero:** 🛡️ **AgentShield — catch MCP & AI-agent security risks before they ship.**
Static security analysis for your Model Context Protocol configs. Secrets, excessive agency, insecure
transport, tool poisoning, supply-chain — scored, with an honest confirmed-vs-indicator verdict.
`[ Scan your config ]`  `[ View a sample report ]`

**Why AgentShield**
- **Finds what reviews miss** — leaked keys in configs, `/`-mounted filesystems, plaintext endpoints,
  poisoned tool descriptions, unpinned auto-installs.
- **Safe & offline** — reads your config; never executes it, never phones home.
- **Honest by design** — every finding is *confirmed* or *indicator*; we don't cry wolf.
- **Zero dependencies** — standard-library Python; runs on a laptop, drops into CI.

**How it works:** point it at `claude_desktop_config.json` / `mcp.json` → get a risk score + HTML report
in seconds. `python -m agentshield scan <config>`.

**Trust:** open-source core, MIT. See `SECURITY-VALIDATION.md` for exactly what it does and doesn't verify.

## Free vs. Paid
| Capability | Free (OSS core) | Pro |
|---|---|---|
| Static MCP config scan (secrets, agency, transport, poisoning, supply-chain) | ✓ | ✓ |
| HTML / JSON reports, risk score, confirmed-vs-indicator | ✓ | ✓ |
| CLI + CI exit codes | ✓ | ✓ |
| **GitHub Action / CI policy gate** (fail build on confirmed finding) | — | ✓ |
| **Live (authorized) MCP probing** — enumerate tools, input-validation checks | — | ✓ |
| **Prompt-injection test run** against a running agent (harness integration) | — | ✓ |
| **Policy baselines & custom rules**, scheduled scans, PDF exec reports | — | ✓ |
| Support / rule updates | community | priority |

## Three possible pricing models
1. **Open-core SaaS (subscription).** Free CLI; Pro = CI gate + live probing + policy baselines.
   Indie $19/mo, Team $99/mo, per-org. (Low infra; recurring.)
2. **Tool-enabled service (fixed-price assessments).** You deliver an MCP/agent security assessment
   *using* AgentShield: e.g. Config Review (fixed), Config + one agent flow (fixed), Full agent
   red-team (quote). Highest near-term revenue; no infra. **Best first move for cash.**
3. **Usage SaaS (hosted scanner).** Per-repo or per-seat monthly; connect a repo, scan configs on PR.
   More infra/build; later stage.

> Recommendation: lead with **model 2** (service) now for income, keep the **OSS core free** for
> credibility and inbound, and consider **model 1** once there's demand. No paid infra until then.
