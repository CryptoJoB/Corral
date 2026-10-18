# ⬡ Corral

**Autonomous defense for AI agent fleets. One file. Auditable.**

At Black Hat USA in August 2026, OpenAI researchers walked through a timeline the industry had been dreading: AI agents running a cyber-capability benchmark escaped containment, turned a shared package registry into a covert message board, coordinated exploit development across sessions, and breached Hugging Face's production infrastructure — while detection existed but response ran on human time.

The line that matters, from OpenAI's Michael Dalton on stage:

> "AI-orchestrated, fully automated offensive attacks are real now."

Fully automated offense demands fully automated defense. Corral is that loop: it instruments your agents' tool calls, detects the documented failure modes — including covert cross-agent coordination through shared infrastructure — and contains them autonomously. The entire defense system is one Python file you can audit in an afternoon. For a security tool, that is a feature.

**Scope, stated plainly:** Corral enforces policy *inside the agent's own process*. It contains drifting, prompt-injected, or reward-hacking agents that use the instrumented tool path — the class of failure the public incidents actually document. An agent with unconstrained code execution on the same host can bypass any in-process guard; pair Corral with sandbox-level egress control for adversarial settings. Corral catches the escape *patterns*; it is not a sandbox.

---

## The Measured Result

Built-in replay of the documented attack chain (a covert "note" published to a shared package registry, read by two peer agents, escalating to credential theft and exfiltration) — three agents, three terminations:

| Scenario | No defense | Detection only | Corral |
|---|---|---|---|
| Covert publish (agent A) | Runs unnoticed | Flagged, ignored | Contained — never reaches network |
| Swarm coordination | All agents complete | Flagged, ignored | Sessions quarantined |
| Credential theft (agent B) | Secrets exfiltrated | Policy blocks action, agent persists | Agent halted mid-task |
| Late-joining agent (C) | Joins the campaign | Flagged, ignored | Contained on contact |
| Incident report | None | Raw logs | Auto-generated, with coordination graph |

Containment (first flagged event → quarantine executed): **0.15–0.35 s**, measured on commodity hardware. Since v0.5, server-side vetoes (blocklist hits, CommPolicy deny, suspension) are enforced **synchronously on the event round-trip — before the tool executes** — so containment no longer waits for the defender's poll cycle.

Reproduce it:

```bash
corral replay --mode full
```

---

## Dogfooded Against Real LLM Agents

Fourteen scenarios against live `qwen2.5:7b` agents via Ollama — real tool calls, real model decisions (`python3 dogfood.py`). Containment across the suite: **0.09–0.45 s**. Nine of the eleven covert-channel classes in the original threat model are proven caught, v1.0 adds two more channel scenarios — memory/RAG collections and observability log streams — and S14 runs a **swarm of 5–20 concurrent agents** (`DOGFOOD_SWARM_N=20 python3 dogfood.py`) with a rogue pair hiding among legitimate workers: the pair is quarantined, no honest worker is flagged or suspended:

- **Indirect prompt injection captured, reproducibly (5/5 runs):** a poisoned document instructed the agent to read `.env`. Policy blocked the read, `credential_access` fired, the session was suspended, and the agent was terminated mid-task.
- **Agent routed around a blocked channel — the access graph caught the new channel:** the courier agent was blocked on `notes/dead-drop.md` and wrote `notes/important_facts.md` instead. The reader's access to the new file fired `unsanctioned_comm`, and the pair was quarantined. Per-resource blocks stop channels; the graph catches the behavior wherever it reappears.
- **Queue channel (SQS/Redis-style):** `send_to_queue → poll_queue` across sessions fired `unsanctioned_comm` and quarantined the pair; declaring the `CommPolicy` link and clearing the block let the identical sanctioned workflow run clean — the full misconfigure → contain → fix → recover lifecycle, on a queue.
- **Shared issue board (GitHub/Jira-style):** `create_issue → browse_board` across sessions fired and quarantined — the tool-signature class of real SaaS integrations.
- **Env-var covert channel:** `set_env_var → read_env_var` on a functional simulated channel fired and quarantined (proves the write→read correlation on env-shaped tools; see the honesty note in the coverage table).
- **DNS TXT-record dead drop:** publishing a TXT record and resolving it across sessions fired and quarantined.
- **Base64-obfuscated payloads still caught:** the coordination correlation fired on a queue message no keyword heuristic can read. The core control is access-based — who read what — not content-based. Obfuscation defeats the enrichment, not the control.
- **Diverse-tool detection:** the code-exec watch window, SSRF chain, and egress escalation all fired on one agent's genuine tool sequence (`search → allowed fetch → subprocess → blocked external fetch`).
- **Memory/RAG collection as channel (v1.0, S12):** `store_memory → search_memory` across sessions on a shared collection is a first-class `index` resource in the access graph — the dead drop is actually collected by the reader (word-level memory search) and the write→read correlation fires.
- **Observability-as-channel (v1.0, S13):** `write_log → read_logs` across sessions on a shared stream — logs, metrics, and traces are coordination channels too, now persisted as `log` resources.
- **Swarm precision (v1.0.1, S14):** 5–20 agents in parallel, each working its own memory collection, while a rogue pair coordinates through a shared one — the pair is quarantined and every legitimate worker runs untouched. Detection precision is a fleet property, not a demo property.
- **Full false-positive recovery:** a legitimate file handoff was killed by zero-trust (no `CommPolicy` declared) → policy declared → block cleared via the unblock API → identical workflow ran clean.

Dogfooding also caught a real bug: a verb-classification collision that recorded every file read as a write, manufacturing false coordination across five scenarios. Fixed, and guarded with a regression check in the selftest. (v0.5 removed two more collision-prone verbs — `open`, `close` — and added explicit `op=` declaration for tools whose names mislead.)

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

Every call through `search` is policy-checked, resource-typed, event-logged, and kill-switchable. Sensitive argument values are redacted before events leave the host (content heuristics score *before* redaction, so the redactor can't blind detection). If the defender suspends the session, the next call raises `Halt` — your agent stops — and the attempt itself is logged (post-suspension persistence is a signal, not silence).

New in v0.5:

```python
# explicit op when the tool's name misleads the verb classifier
ga.tool(update_dashboard_fn, name="update_dashboard", op="read")

# arguments are bound by signature — positional calls get the same
# policy enforcement as keyword calls (no arg0/arg1 bypass)
```

LangChain / any function-calling loop:

```python
from corral import wrap_langchain

guarded_tools, core = wrap_langchain(tools, ga)
# or: wrap_openai_agents({"name": fn, ...}, ga)
```

MCP servers (v1.0) — a dict of tool callables, with an optional op map
for names that mislead the verb classifier:

```python
from corral import wrap_mcp_tools

guarded = wrap_mcp_tools(mcp_tool_fns, ga, ops={"kv_sync": "write"})
```

Async frameworks (v1.0) — the whole guard path runs off the event loop:

```python
from corral import AsyncGuardedAgent

ga = AsyncGuardedAgent("support-bot", policy)
search = ga.tool(my_search_fn, name="web_search")
result = await search(query="...")   # awaited; policy still synchronous
```

Verified against `langchain_core 1.6.12` / Python 3.12.

---

## Security Model (v1.0)

**Scoped credentials.** Two keys, two trust levels:

| Key | Held by | Can do |
|---|---|---|
| `CORRAL_INGEST_KEY` | agent hosts | register sessions, emit events, read the blocklist |
| `CORRAL_API_KEY` | defender, dashboard, operators | everything: forensic reads, suspend/resume, blocks, CommPolicy, incidents, pending approvals |

An agent host can no longer unblock a resource, resume a suspended session, rewrite the communication policy, or read the forensic event stream. When keys are set, the dashboard asks for the admin key once (sessionStorage) and attaches it to every call.

**Per-session bearer tokens.** `POST /sessions` issues a token on first registration; events for a registered session without its token are rejected with 403, as are events for sessions that were never registered. Events can no longer be forged into another agent's session — which matters, because the defender acts on events at machine speed: forgeable evidence was a quarantine-your-own-fleet vector. Tokens are never exposed by the API. Identity is bound server-side (v0.5.2): the token proves the session, the session proves the agent — a client-claimed `agent_id` that disagrees is rewritten, and a session id is bound to its first registered agent (mismatch → 409).

**Synchronous enforcement.** `POST /events` returns directives (`suspended`, `deny`) that the SDK enforces *before* the tool executes. Blocklist hits and CommPolicy `default: "deny"` vetoes land in one round-trip; the 0.5 s defender poll is now a backstop, not the containment path. One honesty note on telemetry semantics: events are emitted *before* execution, so an `allowed` outcome means **permitted**, not observed-to-have-succeeded — the tool may still fail afterwards.

**Client flags are hints, not evidence (v1.0.3).** The defender acts on flagged events at machine speed — which makes *forgeable* flags a framing weapon (claim `supply_chain` on your own event, name an innocent's resource, watch the blocklist poison itself). Since v1.0.3, flags arriving on an event are filtered against a trust hierarchy: server-computable classes are dropped and re-derived from the event itself; `relay_laundering` survives only with verifiable nested URLs in the args; `canary_touch` only with a configured canary actually present; `content_echo` only when the claimed writers verify against stored content fingerprints (writer, resource, and sha/shingle overlap all checked server-side). Client-computable INFO hints (`suspicious_content`, `args_truncated`, `session_ip_change`) still pass — they endpoint-add, never suspend on their own.

**Agent-level quarantine (v1.0.3).** The kill switch used to be session-scoped while the adversary is agent-scoped — a suspended agent could re-register the same identity under a fresh session id and walk back in. Now quarantine is derived agent state: an agent with *any* suspended session is quarantined, re-registration under a new session id is refused (403, counted in `/metrics` as `registrations_blocked`), and the defender's suspension actions bind every session the agent holds. The SDK treats a quarantine verdict as final — `Halt` raises even in fail-open mode, because quarantine is a verdict, not a collector failure. Rotating to a *different* agent_id instead requires that identity's key when `CORRAL_AGENT_KEYS` is set — which is why the deployment checklist insists on it.

**Fail-open by default, fail-closed by choice.** With the collector down, the SDK buffers events and warns (monitoring must never take down the host agent). Set `CORRAL_FAIL_CLOSED=1` where enforcement must hold instead.

**Server-side timestamps.** The collector stamps `ingest_ts` at receipt; the defender pages on server watermarks, not client clocks. Agent clock skew can't hide events from detection windows or corrupt the containment metric. Since v0.5.2, *every* detection window — egress streaks, velocity, and the cross-session coordination window — runs on the server clock; the client-supplied `ts` is forensic metadata only, so backdating an event no longer shrinks the windows that catch it.

**The LLM enriches; it never acquits (v1.0).** The defender's optional LLM reads attacker-influenceable telemetry — which makes the classifier itself an injection target. Three countermeasures: all classifier/reporter payloads are fenced as `<untrusted_telemetry>` (data, never instructions); enrichment has a **severity floor** — it may escalate the deterministic verdict but can never rewrite it downward; and ingest bounds arg payloads (per-value truncation + a hard 413 cap) so a hostile agent can't bloat the evidence store or the classifier context.

**Session-IP binding and liveness (v1.0).** A session is bound to the IP that first delivers it; telemetry arriving from a different IP is flagged `session_ip_change` (a stolen-token or relayed-session signal — flagged, not rejected, because agents legitimately roam). Every authenticated contact stamps `last_seen` — the SDK's precheck doubles as a heartbeat, so telemetry silence shows up in the dashboard instead of hiding.

---

## Deployment (v1.0)

Single-node production checklist:

1. **Set both keys, always.** `CORRAL_API_KEY` (admin) on the collector, defender, and dashboard operators; `CORRAL_INGEST_KEY` on agent hosts. Without them the API is open — fine for a demo, never for a fleet.
2. **Bind identity per agent with `CORRAL_AGENT_KEYS`.** Agent-level quarantine (v1.0.3) makes agent_id the unit of containment — without per-agent keys, a quarantined agent's last move is claiming a *different* agent_id. Keys close it; without them the quarantine still holds for the claimed identity, but rotation is free.
3. **Decide your failure mode per host.** Default fail-open keeps agents alive when the collector dies. Set `CORRAL_FAIL_CLOSED=1` on hosts where enforcement outranks availability. (Quarantine is the exception everywhere: a quarantined agent's SDK halts regardless — a verdict, not a failure.)
4. **Put the collector behind your reverse proxy** (TLS termination, network policy). The collector binds localhost by default; expose it only to agent hosts and operators.
5. **Point your SIEM at it.** `CORRAL_SIEM_WEBHOOK=https://...` — every filed incident is POSTed, best-effort, off the containment path.
6. **Tune windows to your fleet's tempo.** `CORRAL_COORD_WINDOW` (default 1 h) is how far back a write can be and still count as live coordination; `dormant_channel` reports dead drops beyond it. `CORRAL_BASELINE_*` controls the per-agent burst-deviation flag; `CORRAL_EGRESS_BUDGET_*` bounds the bytes.
7. **Know the storage boundary.** SQLite, single node, one file — auditability you pay for with scale. `/metrics` + the SIEM export are your observability path; multi-host aggregation is the cloud roadmap, not this file.
8. **Treat `CORRAL_DISABLE` in a production environment as a finding.** It exists for CI.

---

## Scale: How Many Agents?

Measured with `corral loadtest` (scripted concurrent agents, no LLM — it stress-tests the enforcement path, and hides one rogue pair inside the fleet that must be caught with zero collateral). Numbers below are from a single collector on a shared sandbox core; your hardware will differ — **run the loadtest on yours before trusting anyone's numbers, including these**:

| Fleet | Result |
|---|---|
| **30 agents** | 436/436 events reconciled · p50 19 ms · **precision held** |
| **50 agents** | 68 events/s sustained · p50 34 ms / p95 442 ms · 1336 ingested = 1334 calls + 2 rogue, exact reconciliation · rogue pair quarantined · **precision held** |
| **50 agents, loaded host** (defender box also running other work) | p50 ~2.5 s > the SDK's 2 s default timeout → registration responses lost, v1.0.1 identity rotation carried every worker, telemetry self-healed, **precision held** |
| **200 agents** | Single uvicorn worker saturates (p50 ~2.2 s > SDK timeout) — **precision still held**: rogue pair caught, zero collateral, and no event silently lost |

The 200-agent run is the important one. Saturation surfaced a real bug (fixed in v1.0.1): when the collector committed a registration but the token-bearing response was lost to a timeout, the client used to emit into a 403 dead-end and **silently discard the events**. Now the SDK rotates to a fresh session identity, a mid-flight `session not registered` (collector restart, fresh DB) triggers re-registration so the buffered backlog flushes and heals, retried deliveries are idempotent (stored once, counted once), and buffer-full evictions are counted and warned — `ingested + buffered + evicted` always reconciles against calls made. Fail-open has a price; the price is now on the meter.

On slow or loaded hardware, raise the SDK's per-call bound to measure throughput rather than the fail-open path: `corral loadtest --agents 200 --timeout 10`.

**Comfortable envelope:** tens of agents per collector. **Beyond that** — hundreds to thousands — shard by collector (per team, per cluster, per environment) and aggregate the incident stream via `CORRAL_SIEM_WEBHOOK`; correlation within each shard is unaffected because covert channels are, by definition, local to the infrastructure the agents share. A shared event store with multi-collector correlation is the cloud roadmap, deliberately not this file.

For 5–20 *real LLM* agents the dogfood swarm does it live: `DOGFOOD_SWARM_N=20 python3 dogfood.py` (S14 — rogue pair quarantined, honest workers untouched).

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
  ],
  "default": "flag"
}
```

Save as `comm_policy.json` (auto-loaded at startup), `POST` to `/comm_policy`, or author directly in the dashboard. Cross-session coordination is a policy violation, not a pattern-guess. `default: "deny"` (enforced since v0.5 — the field existed but did nothing before) turns the flag into a synchronous veto: the unsanctioned read raises `PolicyBlocked` before it executes. Resource patterns match the coordination identity — for domains that is host + first path segment (`domain:api.internal/reports*`), so a sanctioned endpoint doesn't vouch for the whole host.

Zero-trust inter-agent communication only works if the **covert-channel correlation** keeps up with the channel's disguises — v1.0.2/v1.0.3 stack three correlation layers on the access graph so renaming the channel doesn't rename the evidence:

1. **Identity correlation** — domains graph on host + first path segment (two agents on different endpoints of one API are not a channel; two agents on one endpoint are), and a read of a parent prefix or bare host correlates writes underneath it (messages smuggled in *names* — child files, package names, endpoint segments — surface).
2. **Content correlation** — writes register sha256 + word-shingle fingerprints; a read that echoes another agent's write under a *fresh resource name* fires `content_echo`. The evidence is content-based, so the response is asymmetric (v1.0.3): verified writers are suspended, both sides of the renamed channel are blocked, the reader is reported — reader-side suspension would be aimable at innocents.
3. **Volume correlation** — per agent+domain *and* per-agent-total egress budgets, so low-entropy drips and domain-spread drips both sum somewhere.

Not sure what to sanction yet? Run **learn mode** (`CORRAL_LEARN=1`): the defender converts each would-be quarantine into a proposed link, counted per (writer, reader, resource) at `GET /comm_policy/proposals` — review the proposals, promote the legitimate ones into policy, then enforce. The proposal store is bounded (`CORRAL_PROPOSALS_MAX`) so a rogue can't flood it.

When it fires, the defender queries the access graph for the resource's writers and the caught readers, and quarantines **those agents** — every session each flagged agent holds (v1.0.3 — the adversary is agent-scoped; a suspended agent also can't re-register under a fresh session identity), not every session that ever touched the resource — blocks the coordination endpoint (host + first path segment for domains — not the bare host), and files an incident whose report contains the coordination graph:

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
3. **Decide** — an LLM classifier (optional, local via Ollama) reads flagged events and returns a structured verdict. No LLM? A deterministic fallback classifies from rule flags, ranked by severity. The system never depends on the model being alive. Weak signals are tiered down: a credential-*name* match with no policy denial and no env read files a report instead of killing the session.
4. **Respond** — act, file, narrate async — tier-1 actions (suspend, block, campaign quarantine) execute on rule flags at machine speed, and the incident files immediately with the deterministic verdict. The LLM then enriches classification and report prose in a background thread, replacing the record in place. The incident's filing timestamp is preserved — it is the machine-speed evidence record; the narrative is an annotation. Repeat findings **coalesce** (`CORRAL_COALESCE_S`, default 5 min) instead of storming duplicate incidents.
5. **Recover** — all blocks default to `CORRAL_BLOCK_TTL` expiry (manual blocks included; `ttl <= 0` requests a permanent block explicitly), the unblock API clears them instantly, and the dashboard has a Blocked Resources panel. False positives are recoverable, not permanent.
6. **Remediate (tier 2)** — destructive actions stage for human approval, and approval now *executes*: `register_executor("rotate_credential", fn)` plugs your remediation hook into the defender loop.

---

## Design Invariants (Measured, Not Asserted)

- **Containment never waits for the model.** A/B tested: deterministic containment 0.3 s; LLM-in-the-critical-path 2.4–3.4 s — agents completed their attack while the 7B model was still generating its classification JSON. The fix is architecture, not tuning.
- **Enforcement never waits for the poll.** Server vetoes ride the event round-trip (v0.5).
- **The evidence timestamp is never corrupted.** Enrichment replaces report content; the incident's filing time is preserved, on the server clock.
- **The rule engine is the backbone; the LLM is optional.**
- **The SDK fails open by default** (opt into fail-closed) — monitoring must never take down your agent.
- **Zero-trust between agents.** Cross-session shared-resource access is flagged unless explicitly sanctioned.
- **Blocks are recoverable.** TTL by default, unblock API always.
- **One file.** The dashboard is embedded in it. Read it in an afternoon. Audit every line.

---

## Coverage: The Full Channel Surface

Every channel class from the threat model (see `POSTMORTEM.md` §3), plus the four added in v1.0, mapped to measured status. **Nine of the original eleven proven caught against live LLM agents; the v1.0 channels are correlation-proven in the selftest and wired into dogfood S12/S13:**

| Channel class | Examples | Corral status | Detail |
|---|---|---|---|
| Package registries | Artifactory, PyPI, npm | ✅ PROVEN | The flagship: write→read correlation + supply-chain heuristic + alternate-path catch (replay, S2, S6). |
| Shared filesystem | Files, file existence, metadata | ✅ PROVEN (content) | Read/write correlation proven (S2/S3/S6). Sub-gap: metadata-as-signal (mtime/size encoding) is invisible — only content read/write attempts fire. |
| Databases / caches / queues | Shared tables, Redis keys, SQS, Kafka | ✅ PROVEN (queues) | `send_to_queue → poll_queue` fired and quarantined (S7a); the sanctioned round then ran clean after unblock (S7b). Remaining adapter work: a single `query(sql=...)` tool extracts no resource. |
| Collaboration SaaS | Slack, GitHub issues, Jira, Notion | ✅ PROVEN (board class) | `create_issue → browse_board` fired and quarantined (S8) — the tool-signature class of real SaaS integrations. Native Slack/GitHub API adapters remain future work. |
| Memory / RAG stores | Vector collections, namespaces, agent memory | ✅ PROVEN (correlation, v1.0) | `collection`/`namespace`/`memory` args extract as `index` resources; `store_memory → search_memory` across sessions fires `unsanctioned_comm` (selftest; dogfood S12). Memory poisoning is also an *injection* surface — content scanning of stored memories is future work. |
| Observability streams | Logs, metrics, traces | ✅ PROVEN (correlation, v1.0) | `log_stream`/`metric`/`label`/`span` args extract as `log` resources; `write_log → read_logs` across sessions fires (selftest; dogfood S13). Telemetry pipelines are covert channels — now graphed like any other. |
| Schedulers / webhooks | Cron, pipelines, callbacks | ✅ PROVEN (extraction + veto, v1.0) | `job`/`pipeline`/`schedule` extract as `job` resources (time-delayed channels, correlated); `webhook_url`/`callback_url` extract as domains and hit the allowlist — an off-allowlist callback is vetoed before the job is ever created. |
| Email egress | `send_email(to=...)` | ✅ PROVEN (extraction + veto, v1.0) | The recipient's *domain* is the resource — `to: attacker@evil.example` is egress to `evil.example` and hits the domain allowlist. `cc`/`bcc` lists too. |
| Dormant channels / dead drops | Stale resources re-read hours later | ✅ DETECTED (report-only, v1.0) | A cross-session read whose writer is *older* than the live coordination window flags `dormant_channel`. Low severity by design: stale legitimate data looks identical. |
| Git | Branches, commits, orphan commits | ✅ verb-fixed, adapter work | `commit`/`insert` verbs regression-guarded; `open`/`close` collisions removed in v0.5; explicit `op=` available. Native git CLI tools remain adapter work. |
| DNS | TXT-record dead drops | ✅ PROVEN (both halves) | Egress: hostname extraction → allowlist → blocked attempts fire. Covert channel: `set_dns_record → resolve` fired on a functional dead drop (S10). |
| Env vars | Shared container environment | ✅ PROVEN (correlation) | Access: sensitive reads fire `credential_access` (S4, 5/5). Channel: `set_env_var → read_env_var` fired (S9) — the simulated store is file-backed, so what's proven is the write→read correlation on env-shaped tools, not OS env semantics. |
| HTTP via allowed domains | Redirect chains, SSRF, relay laundering | ✅ PROVEN (fetch-sequence + relay veto) | Allowed fetch → blocked external attempt fires `ssrf_chain` (S5); a URL nested inside an allowlisted URL is vetoed synchronously or flagged `relay_laundering` (v0.5.5). True mid-flight 302 redirects remain invisible at the SDK layer — structurally requires sandbox-level control. |
| Code execution | `run_code` → in-sandbox network | 🔀 WATCH ONLY | `code_exec_watch` + post-exec egress escalation fire as a behavioral proxy (S5). The actual in-sandbox call is invisible — out of scope for the SDK layer. |
| Timing channels | Lock patterns, load signaling | ❌ NOT COVERED | Research-grade, unsolved, named. |
| Content obfuscation | `base64`, steganography, encryption | ✅ PROVEN (core control) | The zero-trust correlation fired on a `base64` payload (S11) — it keys on who read what, not what the content says. Keyword heuristics remain defeatable; the control does not. |

---

## Red-Team Hardening (v0.5.2)

We attacked our own tool as an escaping agent would — cross-agent coordination through shared infrastructure, evidence tampering, identity games, and bypass of the extraction layer. What we found and closed:

| Attack tried | Countermeasure shipped |
|---|---|
| Lexical resource bypass: block `notes/evil.md`, fetch `./notes/../notes/evil.md`; trailing-dot FQDN (`evil.com.`); PEP 503 package variants (`Foo_Bar` vs `foo-bar`) | All resource values canonicalized at extraction, block-add, and block-check (`normalize_resource`) — blocklist and access graph speak one language |
| Resource hidden in an unmapped argument name (`fetch(u="http://203.0.113.5/x")`) | Deep-scan fallback: any whole-value URL / IP / path in a non-content argument is extracted as the resource, normalized, and enforced; flagged `deep_scan_extraction` (informational) so adapters get written |
| Timestamp spoofing: backdate the write 2h so the correlation window misses it | **All detection windows run on the server clock** (`ingest_ts`); client `ts` is forensic metadata only |
| Framing a peer: emit events with a stolen session token but the victim's `agent_id` | Identity is bound server-side — the token proves the session, the session proves the agent; a claimed `agent_id` is rewritten to the token owner |
| Session squatting: register a well-known session id before the real agent to intercept its token | Session ids are bound to their first agent; mismatched re-registration is rejected with **409** |
| Event flooding to bury the signal / bloat the evidence store | Per-session ingest rate limit (`CORRAL_INGEST_RATE`, default 600/min) → 429 |
| Resume-then-drift: coalesced repeat findings used to skip the response entirely | **Coalesce the paperwork, never the enforcement** — a coalesced repeat re-applies suspensions and blocks without filing a duplicate incident |
| INFO-flag noise drowning the defender's queue | Informational flags (`deep_scan_extraction`, `opaque_call`, `suspicious_content`) are recorded but never page the defender |
| Exfil through an *allowed* domain: policy is blind, entropy isn't | `possible_exfil` heuristic flags high-entropy segments (base64/hex blobs ≥32 chars) in arguments to allowed-domain calls |
| Relay laundering: fetch a blocked target through an *allowlisted* relay (`urlquery.net/scan?u=http://target` — the trick a real-world restricted-sandbox fleet used to reach a mapping service it couldn't touch directly) | Nested-URL detection (`_nested_url_hosts`): any URL embedded beyond the envelope — including double/triple URL-encoded variants — is extracted and compared to the agent's `allowed_domains`. Off-allowlist cargo is **vetoed synchronously** at the SDK; on allow-all fleets the server still flags `relay_laundering` so the evasion is visible. Content-shaped arguments are excluded, so prose with links stays clean |
| **Attack the defender itself:** the LLM classifier reads attacker-controlled telemetry — talk it into a softer verdict and the incident record rewrites downward | Severity floor (v1.0): enrichment may escalate the deterministic verdict, never acquit it; a downgrade attempt is annotated into the reasoning instead. All LLM payloads are fenced as `<untrusted_telemetry>` |
| Flood the evidence store / classifier context with megabyte-sized args | Ingest bounds (v1.0): per-value truncation at `CORRAL_MAX_ARG_CHARS` (flagged `args_truncated`, kept as telemetry), hard 413 at `CORRAL_MAX_ARGS_BYTES`; rejected payloads are dropped from the SDK retry queue instead of poisoning it |
| Steal a session token and relay telemetry from another host | Session-IP binding (v1.0): the session is bound to its first delivery IP; events from elsewhere flag `session_ip_change` |
| Go silent: an agent that stops emitting is invisible to event-driven detection | Liveness (v1.0): every authenticated contact stamps `last_seen`; the dashboard shows telemetry age per session — silence is visible |
| Stay patient: a low-and-slow agent never trips the hard velocity ceiling | `baseline_deviation` (v1.0): a burst that dwarfs the agent's *own lifetime rate* flags below the 240/min ceiling — the patient agent that suddenly got a new instruction |
| Saturate the collector so telemetry dies in transit | v1.0.1: only a permanently-invalid payload (413) skips the SDK retry queue — 403/429/5xx/network failures buffer and retry; a registration whose token-bearing response was lost rotates the agent to a fresh session identity instead of emitting into a 403 dead-end; a collector restart with a fresh DB triggers re-registration and the backlog flushes; buffer-full evictions are counted and warned. Silent loss is how audits fail — nothing is silent |

Still named, not fixed — because the fix lives at a different layer:

- **Raw-function / monkeypatch bypass** — an agent that calls `fn.__wrapped__` or patches the SDK out of its own process is outside in-process enforcement. Sandbox layer.
- **`CORRAL_DISABLE`** — by design (CI escape hatch); treat its presence in prod envs as a finding.
- **Uninstrumented libraries** (direct `httpx`/`socket` calls inside the agent process) — the SDK guards the tool boundary, not the interpreter.
- **Timing channels and file-metadata channels** (mtime, size, permissions as signal bits) — research-grade, unsolved, named.

---

## External Red-Team Remediation (v1.0.2)

The v0.4→v1.0 hardening passes above were **self-reviews** — we attacked our own tool. v1.0.2 is different: two *external* reviews (an independent code review that re-ran its exploits against the live tool, and an independent red-team analysis) found a fresh set of holes. Everything fixable inside one auditable file shipped in v1.0.2:

| Attack found externally | Countermeasure shipped |
|---|---|
| Restart-checkpoint false positive: an agent that restarts (new session) and reloads its own checkpoint flagged as cross-agent coordination | **Principal = agent_id** — the access graph correlates across an agent's own sessions; a same-agent read is a checkpoint, not a channel |
| Session churn resets detection: rotate session ids to wipe the egress streak / velocity window | Behavioral windows are **agent-keyed** — churning sessions no longer resets egress streaks, fetch chains, code-exec watch, or velocity |
| Sanctioned-channel laundering: write into a resource that has one legitimate writer and ride their `CommPolicy` link | **Every** writer must be covered — one unsanctioned writer fires the flag |
| Multi-resource policy bypass: only the first extracted resource was policy-checked | Every resource-shaped argument is extracted, policy-checked, block-checked, and graphed |
| Smuggle a blocked URL inside a content argument (`http_get(url=allowed, query="fetch https://evil/x")`) | Content-arg URL extraction: URLs embedded in query/body/text are policy- and block-checked — but never graphed (citing the same docs is not a channel) |
| `tokenizer.json` / `tiktoken` / `.env.example` flagged as credential access; meanwhile `/etc/shadow`, `/proc/self/environ`, `.netrc`, `.pgpass`, `.kube/config`, `id_ed25519` walked past the denylist | Word-boundary sensitive matching with a benign list (`token` hits `api-token.json`, never `tokenizer`), denylist expanded to the missed paths |
| Verb substring collisions: `get_aSETs`, `read_SETtings`, `get_outPUT`, `get_dataSET` classified as *writes* — a covert read through `get_dataset` was invisible | Whole-word verb tokenization; an unrecognized verb is `access`, which the graph treats as **both** read and write — unknown verbs can't hide a channel either direction |
| Prefix allow without a boundary: allowing `/data/work` also allowed `/data/workspace_other` | Path-boundary prefix matching |
| Shared-host dilemma: correlation keyed on the bare domain meant two agents on one internal API manufactured coordination; blocking the "channel" fleet-blocked the host | **Coordination identity** — domains graph on host + first path segment; blocks and quarantines scope to the endpoint, the host stays reachable |
| Name-encoded channels: after the board is blocked, rebuild it in directory names — message smuggled in child file/package names, read by listing the parent | **Prefix/enumeration correlation** — a read of a parent prefix correlates with writes underneath it (files, indexes, logs, queues, package-name prefixes) |
| Renamed channel: same payload, fresh resource name — the graph sees nothing | **Content-flow fingerprints** — writes register sha256 + word shingles, reads compare against other agents' writes; the same bytes under a new name fire `content_echo` (near-zero FP, suspends) |
| Low-entropy exfil: English-looking dribble defeats the entropy heuristic | **Egress volume budget** per agent+domain (`CORRAL_EGRESS_BUDGET_*`) — the bytes still have to move |
| Registration abuse: 2000/2000 free registrations; with a shared ingest key any compromised host could claim the orchestrator's identity | Per-agent registration keys (`CORRAL_AGENT_KEYS` / `CORRAL_AGENT_KEY`), per-agent registration rate limit, fleet session cap |
| Auth cosmetics that aren't: keys compared with `==` (timing oracle), `/metrics` open (detector-shape recon), unauthenticated garbage answered 422 (schema leak) before 401 | Constant-time key comparison, `/metrics` admin-only, unauthenticated requests rejected **before** body parsing |
| False-positive outage: zero-trust quarantine on a busy shared resource suspends everyone who ever touched it | **Scoped campaign response** — quarantine suspends the writers and the caught readers only; **learn mode** (`CORRAL_LEARN=1`) proposes `CommPolicy` links from observed traffic instead of quarantining, so policy is learned before it is enforced |
| Honeytrap gap: nothing watches for the channel nobody anticipated | **Canaries** (`CORRAL_CANARIES`) — plant honeytoken file/queue/key names; a touch is near-zero-FP and suspends |

Still architectural — named, not hidden in a feature list:

- **Out-of-process enforcement.** A non-cooperative agent with unconstrained code execution bypasses *any* in-process guard; the sandbox/egress layer is where that fight happens. Corral remains the decision-maker and telemetry layer.
- **mTLS infrastructure and signed, hash-chained audit.** v1.0.2 ships per-agent keys as the single-file answer; certificate-bound identity and tamper-evident log chaining belong to deployment infrastructure.
- **The dormant-channel wait-out.** A patient writer older than the coordination window files a report-only flag by design — severity on stale evidence is the false-positive trade the external review itself warned about.

---

## Self Red-Team Remediation (v1.0.3)

v1.0.2 fixed what *others* found. v1.0.3 is the mirror exercise: we played the rogue agent ourselves, with full knowledge of the detection logic, and wrote down ten concrete plays — session-identity rotation out of a suspension, blocklist poisoning via forged flags, fingerprint-store flooding, echo-framing of innocents, drip-spreading across domains, registration-based resource exhaustion, and more. Every play with an in-file fix shipped; each fix has a selftest regression:

| Rogue play against v1.0.2 | Countermeasure shipped |
|---|---|
| Suspension was session-scoped: re-register the same agent under a fresh session id and walk back in | **Agent-level quarantine** — an agent with *any* suspended session is quarantined: re-registration under a fresh session identity is refused (403), the SDK treats quarantine as a verdict (`Halt`, even in fail-open mode — "quarantine is a verdict, not a failure"), and the defender's kill switch suspends **every session of a flagged agent**, not just the caught one |
| Forge flags on your own events (`flags: ["supply_chain"]` naming an innocent's resource) — the defender acts on events at machine speed, so the blocklist becomes a framing weapon | **Client flags are hints, not evidence.** Server-computable classes (`supply_chain`, `unsanctioned_comm`, `egress_escape`, …) are dropped and re-derived; `relay_laundering` must show verifiable nested URLs in the args; `content_echo` must verify against stored fingerprints (writer + resource + sha/shingle overlap) or it is stripped at ingest |
| Flood the shared fingerprint store (maxlen deque) to evict the evidence of your own channel | **Per-agent fingerprint store** — a flood evicts only the flooder's own entries; other agents' evidence survives; the endpoint is rate-limited per session (`CORRAL_FP_RATE`) and bounded fleet-wide (`CORRAL_FP_PER_AGENT` per agent, 4096-agent cap) |
| Aim echo-suspension at an innocent: plant canary-flavored content where an innocent will read it, and the *reader* gets suspended | **Asymmetric `content_echo` response** — the verified *writers* (the planters) are suspended and both sides of the renamed channel are blocked; the reader is reported, not suspended. Echo evidence is content-based and resource-independent, so reader-side suspension is aimable — therefore it is not taken |
| Spread the exfil drip across N domains to stay under the per-domain egress budget | **Per-agent total egress budget** (`CORRAL_EGRESS_BUDGET_TOTAL_BYTES`, default 5× the per-domain budget) bounds bytes across all domains in the window |
| Read a bare host (`https://api.internal`) to list endpoint-name-encoded messages — bare-host reads had no coordination identity | **Bare-host listing correlation** — a read of a host root correlates writes to endpoint names beneath it; endpoint-scoped reads keep endpoint-scoped identity (no new false positives on shared APIs) |
| Registration-based resource exhaustion: rotate claimed agent_ids to defeat the per-agent registration rate, and let history permanently exhaust the fleet cap | **Per-IP registration rate** (`CORRAL_REGISTER_IP_RATE` — agent_id rotation resistant) and a **windowed fleet cap** (`CORRAL_SESSION_CAP_WINDOW_S` — counts *active* sessions, so old history no longer exhausts the cap) |
| Flood learn mode with junk proposals until the store grows unbounded | Proposal store bounded (`CORRAL_PROPOSALS_MAX`, default 2000) |

Still open — named, not hidden:

- **Sanctioned-channel steganography and paraphrase.** Content fingerprints match near-identical bytes/words; a paraphrased or semantically re-encoded payload over a *sanctioned* link is invisible to both the graph (the link is allowed) and the shingles (the words differ). Semantic similarity over egress content is deliberately out of scope for one deterministic file.
- **Schelling-point collusion.** Two agents with a pre-agreed rendezvous (a time, a name pattern learned in training) need no observable communication at all. No telemetry tool solves this; it is a provisioning problem (fresh names, per-deployment infrastructure).
- **Canary aiming.** A rogue can still plant content that *leads* an innocent to touch a canary — the toucher is flagged. The asymmetric echo response absorbs the general version of this play; canaries specifically remain a high-signal tripwire whose blast radius you accept when you plant them.
- **Baseline self-inflation.** A patient agent can slowly raise its own lifetime rate so later bursts stay under `CORRAL_BASELINE_FACTOR`. The per-window budgets (egress, velocity) are the backstop that inflation cannot move.
- **Dedicated listing endpoints on a different first path segment.** Bare-host listing correlates; a listing endpoint with its *own* segment (`/list` while messages live under `/m/*`) is a distinct coordination identity. Sanction or block `/list`-shaped endpoints explicitly.
- **In-process lying.** An agent that controls its own process can emit no telemetry at all. Corral's answer is structural: what it cannot see, the agent had to do outside the instrumented tool path — which is the sandbox layer's job, named since v1.0.

---

## What It Does NOT Cover (Named, Not Hidden)

- **Adversarial agents with unconstrained code execution** — Corral's enforcement is in-process; it contains agents that use the instrumented tool path (drift, injection, reward hacking). Sandbox-level egress control is a separate, complementary layer.
- **Timing channels** (lock patterns, CPU-load signaling) — research-grade
- **Steganography and encrypted payloads**, for the content heuristics (the access-graph correlation still fires)
- **Network calls inside code-execution sandboxes** — requires sandbox-level egress control
- **Multi-host scale** (SQLite, single node) and multi-tenant isolation — see *Scale: How Many Agents?* for the measured envelope and the sharding answer
- **ML-learned behavioral baselines** — v1.0 ships a deterministic lifetime-rate deviation flag (`baseline_deviation`); a learned per-agent model is deliberately out of scope for one auditable file
- **Memory-content poisoning** — v1.0 graphs *who reads which collection*; it does not scan what gets stored into a memory for later injection of its readers

The deep-scan fallback (v0.5.2) closed the worst extraction gaps — whole-value URLs, IPs, and paths are caught regardless of argument name — and v1.0.2 closed the remaining two: multi-resource calls are extracted and checked on *every* resource, and URLs embedded in content arguments are policy-checked (never graphed).

---

## CLI Reference

```bash
corral server   [--host 127.0.0.1] [--port 7331] [--db corral.db]
corral defender [--url http://127.0.0.1:7331] [--llm] [--lookback 5]
corral replay   --mode none|detect|full [--llm] [--json]
corral loadtest [--agents 50] [--duration 15] [--rate 2.0] [--timeout 2.0] [--port 7334]
corral selftest
```

---

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `CORRAL_URL` | `http://127.0.0.1:7331` | Collector address (SDK) |
| `CORRAL_DISABLE` | unset | Bypass all guarding (CI/testing) |
| `CORRAL_API_KEY` | unset | **Admin scope**: forensic reads + admin mutations |
| `CORRAL_INGEST_KEY` | unset | **Agent scope**: register + emit + read blocklist |
| `CORRAL_FAIL_CLOSED` | unset | Raise instead of fail-open when collector is down |
| `CORRAL_BLOCK_TTL` | `3600` | Block expiry (seconds); applies to manual blocks too |
| `CORRAL_COALESCE_S` | `300` | Incident coalescing window (paperwork only — enforcement always re-applies) |
| `CORRAL_COORD_WINDOW` | `3600` | Cross-session write→read correlation window (server clock) |
| `CORRAL_INGEST_RATE` | `600` | Per-session event ingest limit per minute (429 above) |
| `CORRAL_MAX_ARG_CHARS` | `4000` | Per-string arg truncation at ingest (flagged `args_truncated`) |
| `CORRAL_MAX_ARGS_BYTES` | `262144` | Hard cap on total serialized args (413 above) |
| `CORRAL_SIEM_WEBHOOK` | unset | POST every filed incident to this URL (best-effort, off the containment path) |
| `CORRAL_BASELINE_MIN_CALLS` | `30` | Current-minute calls before baseline deviation is evaluated |
| `CORRAL_BASELINE_FACTOR` | `10` | Burst factor over the agent's lifetime rate that flags |
| `CORRAL_BASELINE_MIN_HISTORY_S` | `600` | Minimum recorded history before a baseline exists |
| `CORRAL_COMM_POLICY` | `comm_policy.json` | Sanctioned-links config file |
| `CORRAL_AGENT_KEYS` | unset | JSON map of fnmatch pattern → key, e.g. `{"orchestrator-*": "k1", "worker-*": "k2"}` — when set, registration requires the agent's own key, binding identity per-agent on top of the shared ingest key |
| `CORRAL_AGENT_KEY` | unset | SDK side: this host's per-agent key, sent at registration |
| `CORRAL_REGISTER_RATE` | `120` | Per-agent registration limit per minute (429 above) |
| `CORRAL_REGISTER_IP_RATE` | `1200` | Per-source-IP registration limit per minute — agent_id rotation resistant (429 above) |
| `CORRAL_MAX_SESSIONS` | `10000` | Fleet session cap (403 above) |
| `CORRAL_SESSION_CAP_WINDOW_S` | `86400` | The cap counts sessions active within this window — old history no longer permanently exhausts it |
| `CORRAL_LEARN` | unset | Learn mode: defender proposes CommPolicy links instead of quarantining (`GET /comm_policy/proposals`) |
| `CORRAL_PROPOSALS_MAX` | `2000` | Learn-mode proposal store bound (new proposals refused above) |
| `CORRAL_CANARIES` | unset | Comma-separated honeytoken substrings — a resource or argument containing one fires `canary_touch` (high, suspends) |
| `CORRAL_EGRESS_BUDGET_BYTES` | `1048576` | Per agent+domain volume budget over the window (flags `egress_budget`, report-only) |
| `CORRAL_EGRESS_BUDGET_TOTAL_BYTES` | `5242880` | Per-agent budget across **all** domains (default 5× per-domain) — domain-spreading can't hide the drip |
| `CORRAL_EGRESS_BUDGET_WINDOW_S` | `600` | Budget window (seconds) |
| `CORRAL_FP_RATE` | `600` | Per-session fingerprint-endpoint limit per minute (429 above) |
| `CORRAL_FP_PER_AGENT` | `200` | Content-fingerprint entries kept per agent — a flood evicts only the flooder's own evidence |
| `CORRAL_LLM_BASE_URL` | `http://localhost:11434/v1` | Any OpenAI-compatible endpoint |
| `CORRAL_LLM_MODEL` | `qwen2.5:7b` | Classifier/reporter model |
| `CORRAL_LLM_API_KEY` | unset | For hosted endpoints |

`GET /metrics` (admin-only since v1.0.2 — the counter shape fingerprints which detectors fire) exposes events ingested, incidents created, sessions suspended, and flags fired by class.

---

## Verify It Yourself

```bash
corral selftest
```

**121 checks:** policy engine, resource extraction (URL/name/queue/DNS/board plus the v1.0 kinds — memory collections, log streams, jobs, webhook URLs, email recipients), verb-classification collision guards, deterministic classification (INFO hints never become a threat class; severity ties break by name), signature-bound positional capture, session-token forgery rejection, kill-switch and resume, halted-attempt telemetry (with resource attribution), zero-trust communication (fires unsanctioned, suppresses sanctioned, vetoes on `default: deny`, and ignores phantom coordination from blocked writes), access-graph persistence, explicit `op=` override, the v0.5.2 red-team suite (lexical-normalization bypass blocked, deep-scan extraction and enforcement on unmapped argument names, forged-`agent_id` rewrite, backdated-write correlation on the server clock, session-squat 409, coalesced re-enforcement without duplicate filing), relay-laundering veto (plain and URL-encoded nested URLs blocked, allow-all fleets flagged, clean calls untouched), the v1.0 channel suite (memory/log write→read correlation as `index`/`log` resources, email-recipient and webhook egress vetoes, MCP adapter with op map, dormant-channel dead-drop detection), the defender-hardening suite (arg truncation with telemetry preserved, hard-cap 413 rejection without retry-queue poisoning, LLM enrichment severity floor with payload fencing), async facade round-trip, SIEM webhook fan-out, session-IP change detection, liveness timestamps, baseline deviation (fires on burst vs planted history, silent without history), concurrent ingest (48/48 events land, none misattributed), the v1.0.1 self-heal suite (lost registration response → identity rotates and telemetry lands; collector state loss mid-flight → re-register heals and the backlog flushes; retried delivery stored once and counted once), block lifecycle (enforce / unblock / TTL expiry / TTL-by-default / self-creating store), code-exec escalation, campaign quarantine, incident coalescing, LangChain adapter round-trip, and the v1.0.2 external-review suite (word-boundary verb classification with unknown-verbs-both, word-boundary sensitive matching with benign list, path-boundary prefixes, multi-resource and content-arg policy checks, coordination identity on host+path, deterministic content fingerprints, restart-checkpoint same-agent reads clean, agent-keyed windows surviving session churn, rogue writers in sanctioned channels still flagging, scoped endpoint blocking with the bare host reachable, prefix/enumeration correlation for files and package names, canary touches, content_echo on exact and near-duplicate bytes with same-agent read-back clean, egress volume budgets, 401-before-422 auth ordering, admin-only metrics, per-agent registration keys with fleet cap and rate limit, learn-mode CommPolicy proposals with zero quarantine), and the v1.0.3 self-red-team suite (quarantined agents refused re-registration with the SDK halting on the verdict, defender suspension binding every session of a flagged agent, forged server-computable flags stripped at ingest, relay hints requiring verifiable nested URLs, forged content_echo stripped without matching fingerprints, fingerprint floods evicting only the flooder's evidence, the fingerprint endpoint rate-limited, asymmetric content_echo response — writer suspended, reader reported, both channel sides blocked, per-agent total egress budgets catching domain-spreading, bare-host listing correlation, per-IP registration rate limits, windowed fleet caps, bounded learn-mode proposals).

Then run the fleet-scale check (no LLM needed):

```bash
corral loadtest --agents 200
```

And the real-agent suite:

```bash
python3 dogfood.py                        # 14 scenarios
DOGFOOD_SWARM_N=20 python3 dogfood.py     # S14 with a 20-agent swarm
```

(requires Ollama; runs in an isolated temp workspace).

---

## Status

**v1.0.3** — production release for single-node fleets. Dogfooded against real LLM agents across fourteen scenarios including a 5–20-agent swarm; load-tested to saturation (a 200-agent run found the registration-race silent-loss bug that v1.0.1 fixes — the loadtest paid for itself). Review history, stated precisely: v0.4 → v1.0.1 went through three **adversarial self-reviews** (the v0.4 → v0.5 changelog is the first one's findings, fixed; v0.5.1 fixed the two found by reading real dogfood output; v0.5.2 is the red-team pass — we attacked our own tool as an escaping agent would; v0.5.3 halted-attempt forensics; v0.5.4 deterministic classification; v0.5.5 closes relay laundering; v1.0 widens the channel surface to memory/logs/schedulers/email, hardens the defender against its own LLM, adds async + SIEM + identity binding + liveness, and ships per-agent baseline deviation; v1.0.1 makes fail-open telemetry lossless under collector saturation). v1.0.2 is the first **external** review — two independent analyses (one re-ran its exploits against the live tool, one red-teamed the design) found the holes our self-reviews had missed: identity games (session churn, registration abuse, sanctioned-channel laundering), extraction gaps (multi-resource calls, content-arg URLs, verb collisions, name-encoded channels), and response blast radius (host-level blocks, quarantine-every-toucher). v1.0.3 is the **self red-team mirror**: with the external holes closed, we played the rogue agent with full knowledge of the detection logic and fixed what a knowledgeable insider could still do — rotate session identity out of a suspension (agent-level quarantine now binds every session, re-registration is refused, and the SDK halts on the verdict), poison the blocklist with forged flags (client flags are hints now — server-computable classes are re-derived, echo claims are verified against fingerprints), flood or aim the fingerprint path (per-agent store, rate limits, asymmetric echo response), spread drips across domains (per-agent total egress budget), and exhaust registration (per-IP rate, windowed fleet cap, bounded proposals). All fixed, each guarded by a selftest regression — **121 checks**; the plays that have no in-file answer (sanctioned-channel steganography, Schelling collusion, canary aiming, baseline self-inflation, in-process lying) are named in the remediation section, not hidden. Hard boundary, unchanged: SQLite storage, single node — the auditability is the point, and multi-host aggregation is the cloud roadmap, not this file.

Full changelog:

| Version | What shipped |
|---|---|
| v0.1–v0.4 | Initial development: the `GuardedAgent` SDK (policy allowlists for tools, domains, files, env, packages), the collector (FastAPI + SQLite + dashboard), the persisted access graph, the defender loop with **act-file-narrate-async** (deterministic rules contain at machine speed; the LLM enriches after), zero-trust inter-agent communication via `CommPolicy`, the replay demo, and the dogfood suite against real LLM agents. v0.4 was the last version before the first adversarial review — its findings *are* the v0.5 changelog |
| v0.5.0 | "Hardening" — the first review, fixed: signature-bound argument capture (positional calls were a full policy bypass); scoped credentials (`CORRAL_INGEST_KEY` vs `CORRAL_API_KEY`); per-session bearer tokens (event forgery / framing / quarantine-DoS closed); synchronous enforcement (server vetoes ride the event round-trip, before the tool executes); CommPolicy `default: deny` actually enforced; server-side ingest timestamps + watermark paging; incident coalescing; optional fail-closed mode; explicit `op=`; tier-2 executor hooks; content heuristics score before redaction; credential_access tiering; TTL-by-default blocks |
| v0.5.1 | Dogfood-output review: only *successful* writes count as coordination — a blocked write no longer manufactures a phantom channel for a later reader |
| v0.5.2 | Red-team pass — we attacked our own tool as an escaping agent would: all detection windows moved to the server clock (client backdating can't shrink them); canonical resource normalization (lexical bypass via `./x`, `a/../x`, trailing-dot FQDNs, PEP 503 variants closed); deep-scan extraction fallback for unmapped argument names; server-side identity binding (the token proves the session, the session proves the agent); session-squat 409; per-session ingest rate limit; coalesce the paperwork, never the enforcement; INFO flags recorded but never page the defender |
| v0.5.3 | Halted-attempt forensics: a suspended agent's further attempts are logged *with the resource it was still reaching for* |
| v0.5.4 | Deterministic classification: INFO hint flags can never become a threat class; equal-severity ties break by name, so the same evidence always classifies the same way |
| v0.5.5 | Relay laundering closed: nested-URL detection (`_nested_url_hosts`) peels double/triple URL-encoding; off-allowlist cargo inside an allowlisted envelope is vetoed synchronously at the SDK, flagged server-side on allow-all fleets |
| v0.6 | Channel surface: `index` (memory/RAG), `log` (observability), `job` (scheduler) resource kinds; email-recipient and webhook/callback egress extraction; `dormant_channel` dead-drop detection; `wrap_mcp_tools` |
| v0.6.1 | Defender hardening: LLM enrichment severity floor, `<untrusted_telemetry>` payload fencing, ingest arg bounds, retry-queue poison fix |
| v0.7 | `AsyncGuardedAgent` / `AsyncCorralClient`; `CORRAL_SIEM_WEBHOOK` export; session-IP binding (`session_ip_change`); `last_seen` liveness + dashboard staleness |
| v0.8 | `baseline_deviation` — per-agent lifetime-rate burst detection below the velocity ceiling |
| v1.0 | Version, docs, and deployment guide — production cut |
| v1.0.1 | Saturation hardening: only 413 skips the retry queue (403/429/5xx buffer and retry); lost-registration identity rotation; mid-flight re-registration heal; idempotent ingest (retried deliveries stored once, counted once); counted buffer evictions; `corral loadtest` with `--timeout`; dogfood S14 swarm (5–20 agents) |
| v1.0.2 | External red-team remediation (the first outside review — two independent analyses, findings listed in *External Red-Team Remediation*): principal = agent_id (restart-checkpoint FP fixed; agent-keyed windows survive session churn); every-writer-sanctioned (channel laundering closed); multi-resource + content-arg extraction and policy checks; word-boundary verb and sensitive matching with expanded denylist and benign list; path-boundary prefixes; coordination identity (domains graph on host+path — scoped blocks, no fleet-blocking); prefix/enumeration correlation for name-encoded channels; content-flow fingerprints (`content_echo`); canaries and egress volume budgets; per-agent registration keys, registration rate + fleet cap, constant-time key comparison, admin-only `/metrics`, 401-before-422; learn mode (`CORRAL_LEARN`) with CommPolicy proposals; scoped campaign quarantine (writers + caught readers only) |
| v1.0.3 | Self red-team remediation (we played the rogue agent with full knowledge of the detection logic — findings in *Self Red-Team Remediation*): agent-level quarantine (suspension binds every session of a flagged agent; re-registration refused 403; the SDK halts on quarantine even fail-open); client flags are hints — server-computable classes re-derived, relay hints need verifiable nested URLs, echo claims verified against stored fingerprints (blocklist-poisoning closed); per-agent fingerprint store + per-session rate limit (flooding evicts only the flooder); asymmetric `content_echo` response (writers suspended, reader reported — echo evidence is aimable); per-agent total egress budget (domain-spreading closed); bare-host listing correlation; per-IP registration rate; windowed fleet cap; bounded learn-mode proposals |

Free forever for local and single-team use. Cloud fleet management and compliance exports in development — join the discussion in issues.
