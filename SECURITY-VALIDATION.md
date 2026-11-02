# AgentShield — Security Validation & Detection Limitations

Date: 2026-11-02 · Version: 0.1.0 · Scope: static MCP-config analyzer (MVP)

This document records what AgentShield's detections actually guarantee, what they do
**not**, and the results of an independent quality/security audit of the tool itself.

## 1. Detection model: confirmed vs. indicator
AgentShield labels every finding with a **confidence**, and this is a hard contract:

- **confirmed** — deterministically present in the config and verifiable by re-reading it:
  - a literal provider API key matching a known pattern (`AS-SECRET-001`)
  - a remote server URL using plaintext `http://`/`ws://` (`AS-NET-001`)
- **indicator** — a heuristic signal that is *likely* risky but is **not** proof. It requires
  human review. All other rules are indicators (dangerous command, broad filesystem mount,
  tool-poisoning text, missing auth, unpinned supply chain, secret-like env values).

**We never promote an indicator to "confirmed" without reproducible evidence.** A tool
description that reads like a prompt-injection payload is reported as an *indicator of possible
tool poisoning* — AgentShield does not and cannot prove the description is malicious statically.

## 2. What was validated (audit results)
| Area | Result |
|------|--------|
| MCP config parsing (`mcpServers`/`servers`/bare map, nested) | ✓ parses; recursive string walk covers unknown shapes |
| Secret detection (Anthropic/OpenAI/AWS/GitHub/Google/Slack) | ✓ literal keys → confirmed; env-ref `${VAR}` correctly NOT flagged. OpenAI pattern tightened to real key shapes (project keys / `sk-`+48) so arbitrary `sk-...` build hashes are **not** false-"confirmed" |
| Credentials embedded in a URL (`user:pass@host`) | ✓ confirmed finding (AS-SECRET-004); password masked in ALL url-based evidence, verified no leak |
| Secret **redaction in ALL outputs** (text/HTML/JSON) | ✓ verified: full key value never appears in any format (`test_secret_never_leaks_in_any_format`) |
| Dangerous permission/command detection | ✓ `bash -c`, pipe-to-shell, destructive flags, `/`-mounted filesystem |
| Tool-poisoning indicators | ✓ injection-phrase scan over all strings (indicator only) |
| Risk-score consistency | ✓ deterministic, bounded 0–100 (`test_risk_score_bounded_0_to_100`) |
| Malformed input handling | ✓ **bug fixed**: non-object JSON (list/str/number/None) now returns `AS-INPUT-001` instead of crashing; malformed server shapes (args=str, env=list, server=str) do not crash |
| HTML report escaping / injection resistance | ✓ all config-derived fields `html.escape`d; `<script>` in a server name is neutralised (`test_html_output_escapes_injection`) |
| CLI error handling | ✓ missing file → exit 2; invalid JSON → exit 2; confirmed findings → exit 1; clean → exit 0 |
| Unit test coverage | ✓ 20 tests (vulnerable sample, clean sample, robustness, false-positive, reporting) — all pass |

**Bugs found & fixed (audit + pre-publication review):**
1. `analyze()` raised `AttributeError` on valid JSON that was not an object — fixed with a type guard.
2. Arbitrary `sk-...` strings (e.g. build hashes) were false-labelled *confirmed* OpenAI keys — OpenAI pattern tightened to real key shapes.
3. A password embedded in a server URL leaked into the missing-auth finding's evidence — added a URL-credential masker applied to all URL evidence.
All three have regression tests.

## 3. Known limitations (do not over-trust)
- **Static only.** AgentShield reads config structure. It does not run servers, enumerate live
  tools, test input validation at runtime, or confirm exploitability.
- **Heuristic secret/injection detection.** Expect false positives (a benign string that looks
  like a key/injection) and false negatives (an obfuscated secret or a novel injection phrasing).
  Indicators are leads, not verdicts.
- **Pattern coverage is finite.** New key formats, new dangerous flags, and new config schemas
  may be missed until rules are added.
- **No authorization awareness.** The tool cannot tell whether you are authorized to review a
  given config — that is the operator's responsibility.
- **Not a compliance attestation.** A low score is not a certificate of safety.

## 4. Safe-use statement
AgentShield performs **no execution and no network calls**. It is safe to run on any config you
are authorized to review. Analyze only configurations and systems you own or have **written
authorization** to assess. Sample configs in `samples/` use **fake** values.

## 5. How to reproduce this validation
```bash
python -m unittest discover -s tests -v       # 20 tests
python -m agentshield scan samples/vulnerable_mcp_config.json   # exit 1, redacted findings
python -m agentshield scan samples/clean_mcp_config.json        # exit 0, no confirmed findings
```
