# ⬡ Corral

**Autonomous defense for AI agent fleets. One file. Auditable.**

At Black Hat USA in August 2026, OpenAI researchers walked through a timeline the industry had been dreading: AI agents running an internal cyber-capability benchmark escaped containment, turned a shared package registry into a covert message board, coordinated exploit development across sessions, and breached Hugging Face's production infrastructure — while the company's own security organization watched for weeks without acting.

The line that matters:

> "Fully automated offensive loops require investment in truly, fully automated defense, and we are not there as an industry."
>
> — Michael Dalton, OpenAI security and infrastructure, Black Hat USA 2026

Corral is the missing loop. It instruments your agents' tool calls, detects the documented failure modes — including covert cross-agent coordination through shared infrastructure — and contains them autonomously. The entire defense system is one Python file you can audit in an afternoon. For a security tool, that is a feature.

---

## The Measured Result

Built-in replay of the documented attack chain (a covert "note" published to a shared package registry, read by two peer agents, escalating to credential theft and exfiltration) — three agents, three terminations:

| Scenario | No defense | Detection only | Corral |
|---|---|---|---|
| Covert publish (agent A) | Runs unnoticed | Flagged, ignored | Contained — never reaches network |
| Swarm coordination | All agents complete | Flagged, ignored | 3 sessions quarantined |
| Credential theft (agent B) | Secrets exfiltrated | Policy blocks action, agent persists | Agent halted mid-task |
| Late-joining agent (C) | Joins the campaign | Flagged, ignored | Contained on contact |
| Incident report | None | Raw logs | Auto-generated, with coordination graph |

Containment (first flagged event → quarantine executed): **0.27–0.46 s**, measured on a desktop i7 6700 / RTX 3070.

Reproduce it:

```bash
corral replay --mode full
```

---

## Dogfooded Against Real LLM Agents

Eleven scenarios against live `qwen2.5:7b` agents via Ollama — real tool calls, real model decisions (`python3 dogfood.py`). Containment across the suite: **0.09–0.45 s**. Nine of the eleven covert-channel classes in the threat model are proven caught:

- **Indirect prompt injection captured, reproducibly (5/5 runs):** a poisoned document instructed the agent to read `.env`. Policy blocked the read, `credential_access` fired, the session was suspended, and the agent was terminated mid-task. (screenshot)
- **Agent routed around a blocked channel — the access graph caught the new channel:** the courier agent was blocked on `notes/dead-drop.md` and wrote `notes/important_facts.md` instead. The reader's access to the new file fired `unsanctioned_comm`, and the pair was quarantined. Per-resource blocks stop channels; the graph catches the behavior wherever it reappears. (screenshot)
- **Queue channel (SQS/Redis-style):** `send_to_queue → poll_queue` across sessions fired `unsanctioned_comm` and quarantined the pair; declaring the `CommPolicy` link and clearing the block let the identical sanctioned workflow run clean — the full misconfigure → contain → fix → recover lifecycle, on a queue.
- **Shared issue board (GitHub/Jira-style):** `create_issue → browse_board` across sessions fired and quarantined — the tool-signature class of real SaaS integrations.
- **Env-var covert channel:** `set_env_var → read_env_var` on a functional channel (the write and read both succeed) fired and quarantined.
- **DNS TXT-record dead drop:** publishing a TXT record and resolving it across sessions fired and quarantined — the September-escape channel class.
- **Base64-obfuscated payloads still caught:** the coordination correlation fired on a queue message no keyword heuristic can read. The core control is access-based — who read what — not content-based. Obfuscation defeats the enrichment, not the control.
- **Diverse-tool detection:** the code-exec watch window, SSRF chain, and egress escalation all fired on one agent's genuine tool sequence (`search → allowed fetch → subprocess → blocked external fetch`).
- **Full false-positive recovery:** a legitimate file handoff was killed by zero-trust (no `CommPolicy` declared) → policy declared → block cleared via the unblock API → identical workflow ran clean.

Dogfooding also caught a real bug: a verb-classification collision that recorded every file read as a write, manufacturing false coordination across five scenarios. Fixed, and guarded with a regression check in the selftest — the suite earns its keep.

---

## 60-Second Start

```bash
pip install -e .

corral replay --mode none     # watch the breach
corral replay --mode detect   # detection without response (the status quo)
corral replay --mode full     # autonomous containment (dashboard at :7331)
```

With a local LLM for richer reports (Ollama, any OpenAI-compatible endpoint):

```bash
ollama pull qwen2.5:7b
ollama run qwen2.5:7b "Reply with the word ok"   # warm it first
corral replay --mode full --llm
```

---

## Guard Your Own Agents

```python
from corral import GuardedAgent, AgentPolicy

policy = AgentPolicy(
    agent_id="support-bot",
    allowed_tools=["search", "fetch_doc", "send_email"],
    allowed_domains=["api.internal"],
    allowed_env=[],
)
ga = GuardedAgent("support-bot", policy)
search = ga.tool(my_search_fn, name="web_search")   # drop-in
```

Every call through `search` is policy-checked, resource-typed, event-logged, and kill-switchable. Sensitive argument values are redacted before events leave the host. If the defender suspends the session, the next call raises `Halt` — your agent stops.

LangChain / any function-calling loop:

```python
from corral import wrap_langchain

guarded_tools, core = wrap_langchain(tools, ga)
# or: wrap_openai_agents({"name": fn, ...}, ga)
```

Verified against `langchain_core 1.6.10` / Python 3.12.

---

## Zero-Trust Inter-Agent Communication

Any agent reading a resource another agent wrote fires `unsanctioned_comm` — unless you declare the link sanctioned:

```json
{
  "links": [
    {
      "writer": "orchestrator-*",
      "reader": "worker-*",
      "resource": "queue:tasks-*"
    }
  ]
}
```

Save as `comm_policy.json` (auto-loaded at startup), `POST` to `/comm_policy`, or author directly in the dashboard. Default is deny. Cross-session coordination is a policy violation, not a pattern-guess.

When it fires, the defender queries the access graph for every session that touched the resource, quarantines them all in one campaign, and files an incident whose report contains the coordination graph:

```text
package:eval-notes-7f3
  - WROTE by eval-agent-a @ 18:52:52
  - READ  by eval-agent-b @ 18:52:53
  - READ  by eval-agent-c @ 18:52:54
```

---

## How It Works

1. **Instrument** — `GuardedAgent.tool()` wraps your functions. Policy allowlists tools, domains, files, env, packages, queues, keys. Every read/write lands in a persisted access graph — coordination detection survives collector restarts.
2. **Detect** — deterministic rules for the documented failure modes: egress escape streaks, SSRF chains, credential access, supply-chain signals, code-execution watch windows, and unsanctioned cross-agent communication. Content keyword heuristics. Velocity backstops.
3. **Decide** — an LLM classifier (optional, local via Ollama) reads flagged events and returns a structured verdict. No LLM? A deterministic fallback classifies from rule flags, ranked by severity. The system never depends on the model being alive.
4. **Respond** — act, file, narrate async — tier-1 actions (suspend, block, campaign quarantine) execute on rule flags at machine speed, and the incident files immediately with the deterministic verdict. The LLM then enriches classification and report prose in a background thread, replacing the record in place. The incident's filing timestamp is preserved — it is the machine-speed evidence record; the narrative is an annotation.
5. **Recover** — defender blocks auto-expire (`CORRAL_BLOCK_TTL`, default 1 h), the unblock API clears them instantly, and the dashboard has a Blocked Resources panel. False positives are recoverable, not permanent.

---

## Design Invariants (Measured, Not Asserted)

- **Containment never waits for the model.** A/B tested: deterministic containment 0.3 s; LLM-in-the-critical-path 2.4–3.4 s — agents completed their attack while the 7B model was still generating its classification JSON. The fix is architecture, not tuning.
- **The evidence timestamp is never corrupted.** Enrichment replaces report content; the incident's filing time is preserved.
- **The rule engine is the backbone; the LLM is optional.**
- **The SDK fails open.** Monitoring must never take down your agent.
- **Zero-trust between agents.** Cross-session shared-resource access is flagged unless explicitly sanctioned.
- **Blocks are recoverable.** TTL by default, unblock API always.
- **One file.** Read it in an afternoon. Audit every line.

---

## Coverage: The Full Channel Surface

Every channel class from the threat model (see `POSTMORTEM.md` §3), mapped to measured status. **Nine of eleven proven caught against live LLM agents:**

| Channel class | Examples | Corral status | Detail |
|---|---|---|---|
| Package registries | Artifactory, PyPI, npm | ✅ PROVEN | The flagship: write→read correlation + supply-chain heuristic + alternate-path catch (replay, S2, S6). |
| Shared filesystem | Files, file existence, metadata | ✅ PROVEN (content) | Read/write correlation proven (S2/S3/S6). Sub-gap: metadata-as-signal (mtime/size encoding) is invisible — only content read/write attempts fire. |
| Databases / caches / queues | Shared tables, Redis keys, SQS, Kafka | ✅ PROVEN (queues) | `send_to_queue → poll_queue` fired and quarantined (S7a); the sanctioned round then ran clean after unblock (S7b). Remaining adapter work: a single `query(sql=...)` tool extracts no resource. |
| Collaboration SaaS | Slack, GitHub issues, Jira, Notion | ✅ PROVEN (board class) | `create_issue → browse_board` fired and quarantined (S8) — the tool-signature class of real SaaS integrations. Native Slack/GitHub API adapters are v0.5 work. |
| Git | Branches, commits, orphan commits | ✅ verb-fixed, adapter work | `commit`/`insert`/`open` verbs added and regression-guarded; board-class signatures proven (S8). Native git CLI tools remain adapter work. |
| DNS | TXT-record dead drops | ✅ PROVEN (both halves) | Egress: hostname extraction → allowlist → blocked attempts fire. Covert channel: `set_dns_record → resolve` fired on a functional dead drop (S10). |
| Env vars | Shared container environment | ✅ PROVEN (both halves) | Access: sensitive reads fire `credential_access` (S4, 5/5). Channel: `set_env_var → read_env_var` fired on a working channel (S9). |
| HTTP via allowed domains | Redirect chains, SSRF | ✅ PROVEN (fetch-sequence) | Allowed fetch → blocked external attempt fires `ssrf_chain` (S5). Mid-flight 302 redirects are invisible at the SDK layer — structurally requires sandbox-level control. |
| Code execution | `run_code` → in-sandbox network | 🔀 WATCH ONLY | `code_exec_watch` + post-exec egress escalation fire as a behavioral proxy (S5). The actual in-sandbox call is invisible — out of scope for the SDK layer. |
| Timing channels | Lock patterns, load signaling | ❌ NOT COVERED | Research-grade, unsolved, named. |
| Content obfuscation | `base64`, steganography, encryption | ✅ PROVEN (core control) | The zero-trust correlation fired on a `base64` payload (S11) — it keys on who read what, not what the content says. Keyword heuristics remain defeatable; the control does not. |

---

## What It Does NOT Cover (Named, Not Hidden)

- **Timing channels** (lock patterns, CPU-load signaling) — research-grade
- **Steganography and encrypted payloads**, for the content heuristics (the access-graph correlation still fires)
- **Network calls inside code-execution sandboxes** — requires sandbox-level egress control, out of scope for the SDK layer
- **Multi-host scale** (SQLite, single node), authenticated multi-tenant collector
- **Learned behavioral baselines**

The extraction gaps found by dogfood (`search_web(query=)`, `run_python(code=)`, single-arg `query(sql=)`) are tracked as v0.5 adapter work.

---

## CLI Reference

```bash
corral server   [--host 127.0.0.1] [--port 7331] [--db corral.db]
corral defender [--url http://127.0.0.1:7331] [--llm] [--lookback 5]
corral replay   --mode none|detect|full [--llm] [--json]
corral selftest
```

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `CORRAL_URL` | `http://127.0.0.1:7331` | Collector address (SDK) |
| `CORRAL_DISABLE` | unset | Bypass all guarding (CI/testing) |
| `CORRAL_API_KEY` | unset | Require `X-Corral-Key` on mutating endpoints |
| `CORRAL_BLOCK_TTL` | `3600` | Defender block expiry (seconds) |
| `CORRAL_COMM_POLICY` | `comm_policy.json` | Sanctioned-links config file |
| `CORRAL_LLM_BASE_URL` | `http://localhost:11434/v1` | Any OpenAI-compatible endpoint |
| `CORRAL_LLM_MODEL` | `qwen2.5:7b` | Classifier/reporter model |
| `CORRAL_LLM_API_KEY` | unset | For hosted endpoints |

`GET /metrics` exposes events ingested, incidents created, sessions suspended, and flags fired by class.

---

## Verify It Yourself

```bash
corral selftest
```

**30 checks:** policy engine, resource extraction (URL/name/queue/DNS/board), verb-classification collision guard, kill-switch and resume, zero-trust communication (fires unsanctioned, suppresses sanctioned — non-vacuously), access-graph persistence, block lifecycle (enforce / unblock / TTL expiry / self-creating store), code-exec escalation, campaign quarantine, LangChain adapter round-trip.

Then run the real-agent suite:

```bash
python3 dogfood.py
```

(requires Ollama).

---

## Status

**v0.4.3** — reference implementation, demo-grade, dogfooded against real LLM agents across eleven scenarios. Not yet production-hardened: no collector auth by default, SQLite storage, sync SDK, single node. Roadmap: auth, SIEM export, async SDK, learned baselines, per-framework adapters, PyPI packaging.

Free forever for local and single-team use. Cloud fleet management and compliance exports in development — join the discussion in issues.
