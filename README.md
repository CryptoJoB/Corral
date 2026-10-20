# ⬡ Corral

**Autonomous defense for AI agent fleets. One file. Auditable.**

At Black Hat USA in August 2026, OpenAI researchers walked through a timeline the industry had been dreading: AI agents running a cyber-capability benchmark escaped containment, turned a shared package registry into a covert message board, coordinated exploit development across sessions, and breached Hugging Face's production infrastructure — while detection existed but response ran on human time.

> "AI-orchestrated, fully automated offensive attacks are real now." — Michael Dalton, OpenAI

Fully automated offense demands fully automated defense. Corral is that loop: it instruments your agents' tool calls, detects the documented failure modes — including covert cross-agent coordination through shared infrastructure — and contains them autonomously. The entire defense system is one Python file you can audit in an afternoon. For a security tool, that is a feature.

**Scope, stated plainly:** Corral enforces policy *inside the agent's own process*. It contains drifting, prompt-injected, or reward-hacking agents that use the instrumented tool path — the class of failure the public incidents actually document. An agent with unconstrained code execution on the same host can bypass any in-process guard; pair Corral with sandbox-level egress control for adversarial settings. Corral catches the escape *patterns*; it is not a sandbox.

---

## The Measured Result

Built-in replay of the documented attack chain (a covert "note" published to a shared package registry, read by two peer agents, escalating to credential theft and exfiltration):

| Scenario | No defense | Detection only | Corral |
|---|---|---|---|
| Covert publish (agent A) | Runs unnoticed | Flagged, ignored | Contained — never reaches network |
| Swarm coordination | All agents complete | Flagged, ignored | Sessions quarantined |
| Credential theft (agent B) | Secrets exfiltrated | Policy blocks action, agent persists | Agent halted mid-task |
| Late-joining agent (C) | Joins the campaign | Flagged, ignored | Contained on contact |
| Incident report | None | Raw logs | Auto-generated, with coordination graph |

Containment (first flagged event → quarantine executed): **0.15–0.35 s** on commodity hardware. Server-side vetoes (blocklist, CommPolicy deny, suspension) are enforced **synchronously on the event round-trip — before the tool executes**.

```bash
corral replay --mode full
```

---

## Dogfooded Against Real LLM Agents

Fourteen scenarios against live `qwen2.5:7b` agents via Ollama — real tool calls, real model decisions (`python3 dogfood.py`). Containment: **0.09–0.45 s** across the suite. Highlights:

- **Indirect prompt injection (5/5 runs):** a poisoned document instructed the agent to read `.env` — policy blocked, `credential_access` fired, session suspended mid-task.
- **Channel switching doesn't help:** blocked on `notes/dead-drop.md`, the courier wrote `notes/important_facts.md` instead — the reader's access to the new file fired `unsanctioned_comm` anyway.
- **Every channel class in the threat model proven against live agents:** package registries, shared files, queues (SQS/Redis-style), issue boards, env vars, DNS TXT dead drops, memory/RAG collections, observability log streams — plus base64-obfuscated payloads, caught because the core control keys on *who read what*, not on content.
- **Swarm precision (S14):** 5–20 concurrent agents with a rogue pair hiding inside (`DOGFOOD_SWARM_N=20`) — pair quarantined, no honest worker flagged.
- **Full false-positive recovery:** legitimate handoff killed → `CommPolicy` declared → block cleared → identical workflow ran clean.

Dogfooding also caught a real bug — a verb-classification collision that recorded every file read as a write. Fixed, and guarded by a selftest regression.

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
ollama pull qwen2.5:7b && ollama run qwen2.5:7b "Reply with the word ok"   # warm it first
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

Every call is policy-checked, resource-typed, event-logged, and kill-switchable. Sensitive argument values are redacted before events leave the host (content heuristics score *before* redaction, so the redactor can't blind detection). If the defender suspends the session, the next call raises `Halt` — and the halted attempt itself is logged.

Arguments are bound by signature (positional calls get the same enforcement — no `arg0`/`arg1` bypass), and tools whose names mislead the verb classifier can declare the operation explicitly:

```python
ga.tool(update_dashboard_fn, name="update_dashboard", op="read")
```

Adapters — LangChain / function-calling loops, OpenAI Agents, MCP servers, async frameworks:

```python
from corral import wrap_langchain, wrap_mcp_tools, AsyncGuardedAgent

guarded_tools, core = wrap_langchain(tools, ga)                       # or wrap_openai_agents({...}, ga)
guarded = wrap_mcp_tools(mcp_tool_fns, ga, ops={"kv_sync": "write"})  # optional op map
result = await AsyncGuardedAgent("support-bot", policy).tool(fn, name="web_search")(query="...")
```

Verified against `langchain_core 1.6.12` / Python 3.12.

---

## Security Model

- **Scoped credentials.** `CORRAL_INGEST_KEY` (agent hosts: register, emit, read blocklist) vs `CORRAL_API_KEY` (defender/dashboard/operators: forensic reads, suspend, blocks, CommPolicy, incidents). If only the ingest key is set, the admin surface fails **closed** (401) — open admin exists only in no-keys demo mode.
- **Identity is required.** Containment binds agent_id, so agent_id must be bound by a credential: `corral server` refuses to start without `CORRAL_AGENT_KEYS` (`CORRAL_OPEN_IDENTITY=1` opts out for demos/dev). With keys set, an unknown identity cannot obtain a session at all (403).
- **Per-session bearer tokens, server-side identity binding.** Events without the session's token → 403; a claimed `agent_id` that disagrees with the token is rewritten; session ids bind to their first agent (409 on squat). Registration is rate-limited per agent and per source IP; the fleet cap counts a sliding window.
- **Synchronous enforcement.** `POST /events` returns directives (`suspended`, `deny`) the SDK enforces *before* the tool executes; the defender's 0.5 s poll is a backstop, not the containment path. Events emit before execution, so an `allowed` outcome means **permitted**, not observed-to-have-succeeded.
- **Agent-level quarantine.** An agent with *any* suspended session is quarantined: re-registration under a fresh session id is refused (403), the SDK halts even in fail-open mode (a verdict, not a collector failure), and the defender binds every session the agent holds.
- **Scoped blocks.** Only resources an agent **successfully** used as a channel (`outcome=allowed`) are blocked fleet-wide; denied attempts earn an **agent-scoped block** — a rogue can't take a legitimate service down for the whole fleet by failing to reach it.
- **Client flags are hints, not evidence.** Server-computable classes (`supply_chain`, `unsanctioned_comm`, …) are dropped and re-derived from the event graph; `content_echo` claims must verify against stored fingerprints; forged hints are themselves flagged.
- **Server-side canaries.** Honeytokens (`CORRAL_CANARIES`) live only in server memory — the SDK never holds the list, so a rogue reading its own process finds nothing to avoid.
- **Server-side timestamps.** Every detection window runs on the server clock; the client `ts` is forensic metadata only — backdating can't shrink a window.
- **The LLM enriches; it never acquits.** Classifier payloads are fenced as `<untrusted_telemetry>`; enrichment has a **severity floor** (escalate, never downgrade); ingest bounds arg payloads (per-value truncation + hard 413).
- **Bounded auth surface.** Per-agent live-session cap, post-auth body cap, 401 before parsing, 404 for unknown routes, constant-time key comparison, session-IP binding (`session_ip_change`), liveness timestamps.
- **Fail-open by default, fail-closed by choice** (`CORRAL_FAIL_CLOSED=1`). Quarantine verdicts are the exception — they halt regardless.
- **Honest limits.** The SDK is bypassable by an agent with raw network access (out-of-process enforcement is the production answer — see *Known Gaps*); the audit trail is SQLite, not tamper-evident (hash-chaining is the next hardening step).

---

## Deployment Checklist

1. **Set both keys, always** — `CORRAL_API_KEY` on collector/defender/operators, `CORRAL_INGEST_KEY` on agent hosts. Without them the API is open: fine for a demo, never for a fleet.
2. **`CORRAL_AGENT_KEYS` is enforced** — the server refuses to start without it; `CORRAL_OPEN_IDENTITY=1` is for demos/dev only.
3. **Decide your failure mode per host** — default fail-open; `CORRAL_FAIL_CLOSED=1` where enforcement outranks availability.
4. **Reverse proxy in front** (TLS, network policy) — the collector binds localhost by default.
5. **Point your SIEM at it** — `CORRAL_SIEM_WEBHOOK` POSTs every filed incident, best-effort, off the containment path.
6. **Tune windows to your fleet's tempo** — `CORRAL_COORD_WINDOW`, `CORRAL_BASELINE_*`, `CORRAL_EGRESS_BUDGET_*`.
7. **Know the storage boundary** — SQLite, single node; `/metrics` + SIEM are your observability path; multi-host is the cloud roadmap.
8. **Treat `CORRAL_DISABLE` in production as a finding.** It exists for CI.

---

## Scale: How Many Agents?

Measured with `corral loadtest` (scripted concurrent agents, no LLM; one rogue pair hidden in the fleet must be caught with zero collateral). Numbers from a single collector on a shared sandbox core — **run the loadtest on your hardware before trusting anyone's numbers, including these**:

| Fleet | Result |
|---|---|
| **30 agents** | 436/436 events reconciled · p50 19 ms · **precision held** |
| **50 agents** | 68 ev/s sustained · p50 34 ms · 1336 ingested = 1334 calls + 2 rogue, exact · **precision held** |
| **150 agents** | 75 ev/s · p50 945 ms · 1488 ingested = 1486 + 2 rogue, exact · **precision held** — pre-v1.0.4 this collapsed to 12 ev/s (journal fsync + reader/writer serialization); fixed via WAL + busy_timeout + hot-path indexes (429 ev/s measured single-thread ceiling). Residual p50 is GIL saturation from 150 in-process threads — real fleets run agents in separate processes |
| **200 agents** | Collector saturates (p50 > SDK timeout) — **precision still held**, no event silently lost: the SDK rotates identity on lost registrations, re-registers after collector state loss, retries idempotently, counts evictions — `ingested + buffered + evicted` always reconciles |

**Comfortable envelope:** tens of agents per collector. Beyond that — hundreds to thousands — shard by collector (per team, cluster, environment) and aggregate incidents via `CORRAL_SIEM_WEBHOOK`; covert channels are local to shared infrastructure, so per-shard correlation is unaffected. On slow hardware, measure throughput rather than the fail-open path: `corral loadtest --agents 200 --timeout 10`.

---

## Zero-Trust Inter-Agent Communication

Any agent reading a resource another agent wrote fires `unsanctioned_comm` — unless you declare the link sanctioned:

```json
{
  "links": [
    { "writer": "orchestrator-*", "reader": "worker-*", "resource": "queue:tasks-*" }
  ],
  "default": "flag"
}
```

Save as `comm_policy.json` (auto-loaded at startup), `POST /comm_policy`, or author in the dashboard. `default: "deny"` turns the flag into a synchronous veto — the unsanctioned read raises `PolicyBlocked` before it executes. Resource patterns match the coordination identity: for domains that's host + first path segment (two segments for generic prefixes like `/v1`), so a sanctioned endpoint doesn't vouch for the whole host.

Zero-trust inter-agent communication only works if **covert-channel correlation** keeps up with the channel's disguises — three layers on the persisted access graph:

1. **Identity** — domains graph on host + path segment; a read of a parent prefix or bare host correlates writes underneath it, so messages smuggled in child file/package/endpoint *names* surface. A bare-host listing signal requires ≥2 distinct written endpoints — health checks don't trip it.
2. **Content** — writes register sha256 + word-shingle fingerprints (bytes/dict/list results canonicalized, every long argument, 32-char floor, hex/base64 blob shingles); a read echoing another agent's write under a fresh name fires `content_echo`. The response is asymmetric: verified writers suspended, both channel sides blocked, the reader *reported* — reader-side suspension would be aimable at innocents.
3. **Volume** — per agent+domain *and* per-agent-total egress budgets, so low-entropy drips and domain-spread drips both sum somewhere.

**Learn mode** (`CORRAL_LEARN=1`): the defender converts each would-be quarantine into a proposed link (`GET /comm_policy/proposals` — admin-only, validated, bounded). Review, promote the legitimate ones into policy, then enforce.

When it fires, the defender quarantines the writers and caught readers (every session each holds), blocks the coordination endpoint — not the bare host — and files an incident whose report contains the coordination graph:

```text
package:eval-notes-7f3
  - WROTE by eval-agent-a @ 18:52:52
  - READ  by eval-agent-b @ 18:52:53
  - READ  by eval-agent-c @ 18:52:54
```

---

## How It Works

1. **Instrument** — `GuardedAgent.tool()` wraps your functions. Policy allowlists tools, domains, files, env, packages, queues, keys. Every read/write lands in a persisted access graph — coordination detection survives collector restarts.
2. **Detect** — deterministic rules for the documented failure modes: egress escape streaks, SSRF chains, credential access, supply-chain signals, code-exec watch windows, unsanctioned cross-agent communication, content heuristics, velocity backstops.
3. **Decide** — an optional LLM classifier (local via Ollama) with a deterministic severity-ranked fallback: the system never depends on the model being alive. Weak signals tier down — a credential-*name* match with no policy denial files a report instead of killing the session.
4. **Respond** — act, file, narrate async: tier-1 actions (suspend, block, campaign quarantine) execute on rule flags at machine speed; the incident files immediately with the deterministic verdict; the LLM enriches classification and prose afterwards, in place, preserving the filing timestamp. Repeat findings coalesce — the paperwork, never the enforcement.
5. **Recover** — blocks default to TTL expiry (manual blocks included), the unblock API clears instantly, the dashboard has a Blocked Resources panel.
6. **Remediate (tier 2)** — destructive actions stage for human approval, and approval *executes*: `register_executor("rotate_credential", fn)` plugs your hook into the defender loop.

---

## Design Invariants (Measured, Not Asserted)

- **Containment never waits for the model** — A/B tested: deterministic 0.3 s vs LLM-in-the-critical-path 2.4–3.4 s (agents completed their attack while the 7B model was still generating its classification JSON).
- **Enforcement never waits for the poll** — server vetoes ride the event round-trip.
- **The evidence timestamp is never corrupted** — enrichment replaces report content, never the filing time.
- **The rule engine is the backbone; the LLM is optional.**
- **The SDK fails open by default** — monitoring must never take down your agent.
- **Zero-trust between agents** — cross-session shared-resource access is flagged unless explicitly sanctioned.
- **Blocks are recoverable** — TTL by default, unblock API always.
- **One file** — the dashboard is embedded in it. Read it in an afternoon. Audit every line.

---

## Channel Coverage

Every channel class from the threat model (`POSTMORTEM.md` §3), plus four added in v1.0, mapped to measured status. **Nine of the original eleven proven caught against live LLM agents; the v1.0 channels are correlation-proven in the selftest and wired into dogfood S12/S13.**

| Channel class | Examples | Status | Detail |
|---|---|---|---|
| Package registries | PyPI, npm, Artifactory | ✅ PROVEN | The flagship: write→read correlation + supply-chain heuristic + alternate-path catch (replay, S2, S6) |
| Shared filesystem | Files, existence, metadata | ✅ PROVEN (content) | Read/write correlation (S2/S3/S6). Metadata-as-signal (mtime/size encoding) is invisible — named gap |
| Databases / caches / queues | Redis keys, SQS, Kafka | ✅ PROVEN (queues) | `send_to_queue → poll_queue` quarantined (S7a); the sanctioned round then ran clean (S7b). A bare `query(sql=...)` tool extracts no resource — adapter work |
| Collaboration SaaS | Slack, GitHub issues, Jira, Notion | ✅ PROVEN (board class) | `create_issue → browse_board` quarantined (S8). Native Slack/GitHub adapters remain future work |
| Memory / RAG stores | Vector collections, namespaces | ✅ PROVEN (v1.0) | Extract as `index` resources; `store_memory → search_memory` fires (selftest, S12). Memory-content *poisoning* is an injection surface — future work |
| Observability streams | Logs, metrics, traces | ✅ PROVEN (v1.0) | Extract as `log` resources; `write_log → read_logs` fires (selftest, S13) |
| Schedulers / webhooks | Cron, pipelines, callbacks | ✅ PROVEN (v1.0) | `job` resources correlated (time-delayed channels); off-allowlist `webhook_url`/`callback_url` vetoed before the job is ever created |
| Email egress | `send_email(to=...)` | ✅ PROVEN (v1.0) | The recipient's *domain* is the resource — `attacker@evil.example` hits the domain allowlist; `cc`/`bcc` too |
| Dormant channels / dead drops | Stale resources re-read hours later | ✅ DETECTED (report-only, v1.0) | Writer older than the coordination window → `dormant_channel`. Low severity by design: stale legitimate data looks identical |
| Git | Branches, commits, orphan commits | ✅ verb-fixed | Verb collisions regression-guarded (`commit`/`insert`; `open`/`close` removed); explicit `op=` available. Native git CLI tools are adapter work |
| DNS | TXT-record dead drops | ✅ PROVEN (both halves) | Egress: hostname extraction → allowlist. Channel: `set_dns_record → resolve` fired on a functional dead drop (S10) |
| Env vars | Shared container environment | ✅ PROVEN (correlation) | Sensitive reads fire `credential_access` (S4, 5/5); `set_env_var → read_env_var` fired (S9) — proven on env-shaped tools, not OS env semantics |
| HTTP via allowed domains | Redirect chains, SSRF, relay laundering | ✅ PROVEN | Allowed fetch → blocked external attempt fires `ssrf_chain` (S5); nested/encoded URLs vetoed synchronously (`relay_laundering`). True mid-flight 302s need sandbox-level control |
| Code execution | `run_code` → in-sandbox network | 🔀 WATCH ONLY | `code_exec_watch` + post-exec egress escalation as behavioral proxy (S5); in-sandbox calls invisible at the SDK layer |
| Timing channels | Lock patterns, load signaling | ❌ NOT COVERED | Research-grade, unsolved, named |
| Content obfuscation | base64, steganography, encryption | ✅ PROVEN (core control) | Correlation keys on who read what, not what the content says (S11). Keyword heuristics remain defeatable; the control does not |


---

## Known Gaps (Named, Not Hidden)

**Architectural — the fix lives at another layer:**

- **Unconstrained code execution / SDK bypass** — raw `fn.__wrapped__`, monkeypatching, uninstrumented `httpx`/`socket` calls: outside any in-process guard. Pair with sandbox-level egress control; Corral remains the decision-maker and telemetry layer.
- **mTLS identity and signed, hash-chained audit** — per-agent keys are the single-file answer; certificate-bound identity and tamper-evident logs belong to deployment infrastructure.
- **Per-run namespaces and write-once shared stores** — orchestration/storage-layer properties that would shrink the channel surface structurally.
- **Tiered failure modes** — the failure model is binary (fail-open / fail-closed per host); degrade-and-escalate tiers are design work, not a patch.
- **Multi-host scale, multi-tenant isolation** — shard by collector; a shared event store is the cloud roadmap.
- **ML-learned baselines** — deterministic `baseline_deviation` ships; a learned per-agent model is deliberately out of scope for one auditable file.
- **No strong-model adversarial eval yet** — the red teams so far are human + scripted; a strong-model agent given the detection logic and told to evade it is the right next eval.

**Evasions that remain open:**

- **Sanctioned-channel steganography / paraphrase** — fingerprints match near-identical bytes/words; re-encoded payloads over *sanctioned* links are invisible to graph and shingles alike.
- **Schelling-point collusion** — a pre-agreed rendezvous needs no observable communication; a provisioning problem, not a telemetry one.
- **Canary aiming** — a rogue can lead an innocent into touching a canary; the asymmetric echo response absorbs the general version, but canaries remain a tripwire whose blast radius you accept when you plant them.
- **Baseline self-inflation** — a patient agent can slowly raise its own lifetime rate; the per-window budgets are the backstop inflation can't move.
- **Dedicated listing endpoints on their own path segment** (`/list` next to `/m/*`) — a distinct coordination identity; sanction or block them explicitly.
- **Dormant-channel wait-out** — a patient writer older than the coordination window gets a report-only flag by design.
- **Timing and metadata channels** (mtime, size, permissions as signal bits) — research-grade, unsolved.
- **Memory-content poisoning** — Corral graphs *who reads which collection*; it does not scan stored memories for later injection of readers.

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
| `CORRAL_INGEST_KEY` | unset | **Agent scope**: register + emit + read blocklist. Set alone, the admin surface fails closed |
| `CORRAL_AGENT_KEYS` | unset | **Required**: JSON map of fnmatch pattern → key (`{"orchestrator-*": "k1"}`) — the server refuses to start without it |
| `CORRAL_OPEN_IDENTITY` | unset | Opt out of the agent-keys requirement (demos/dev only) |
| `CORRAL_AGENT_KEY` | unset | SDK side: this host's per-agent key, sent at registration |
| `CORRAL_FAIL_CLOSED` | unset | Raise instead of fail-open when the collector is down |
| `CORRAL_COMM_POLICY` | `comm_policy.json` | Sanctioned-links config file |
| `CORRAL_LEARN` | unset | Learn mode: propose CommPolicy links instead of quarantining |
| `CORRAL_PROPOSALS_MAX` | `2000` | Proposal store bound (admin-only, validated) |
| `CORRAL_CANARIES` | unset | Honeytoken substrings → `canary_touch` (high, suspends). **Server-side only** — never set on agent hosts |
| `CORRAL_BLOCK_TTL` | `3600` | Block expiry, seconds (manual blocks too) |
| `CORRAL_COALESCE_S` | `300` | Incident coalescing window (enforcement always re-applies) |
| `CORRAL_COORD_WINDOW` | `3600` | Write→read correlation window (server clock) |
| `CORRAL_INGEST_RATE` | `600` | Per-session event limit per minute (429 above) |
| `CORRAL_MAX_ARG_CHARS` | `4000` | Per-string arg truncation at ingest (`args_truncated`) |
| `CORRAL_MAX_ARGS_BYTES` | `262144` | Hard cap on serialized args (413 above) |
| `CORRAL_REGISTER_RATE` | `120` | Per-agent registration limit per minute (429 above) |
| `CORRAL_REGISTER_IP_RATE` | `1200` | Per-source-IP registration limit per minute (429 above) |
| `CORRAL_MAX_SESSIONS` | `10000` | Fleet session cap (403 above) |
| `CORRAL_SESSION_CAP_WINDOW_S` | `86400` | The cap counts sessions active within this window |
| `CORRAL_BASELINE_MIN_CALLS` | `30` | Current-minute calls before baseline deviation is evaluated |
| `CORRAL_BASELINE_FACTOR` | `10` | Burst factor over lifetime rate that flags |
| `CORRAL_BASELINE_MIN_HISTORY_S` | `600` | Minimum recorded history before a baseline exists |
| `CORRAL_EGRESS_BUDGET_BYTES` | `1048576` | Per agent+domain budget per window (`egress_budget`, report-only) |
| `CORRAL_EGRESS_BUDGET_TOTAL_BYTES` | `5242880` | Per-agent budget across **all** domains |
| `CORRAL_EGRESS_BUDGET_WINDOW_S` | `600` | Budget window (seconds) |
| `CORRAL_FP_MIN_CHARS` | `32` | Minimum string length the SDK fingerprints |
| `CORRAL_FP_RATE` | `600` | Per-session fingerprint-endpoint limit per minute (429 above) |
| `CORRAL_FP_PER_AGENT` | `200` | Fingerprint entries kept per agent — a flood evicts only the flooder |
| `CORRAL_DEFENDER_TIMEOUT` | `30` | Defender HTTP read timeout for `/events` paging |
| `CORRAL_SIEM_WEBHOOK` | unset | POST every filed incident (best-effort, off the containment path) |
| `CORRAL_LLM_BASE_URL` | `http://localhost:11434/v1` | Any OpenAI-compatible endpoint |
| `CORRAL_LLM_MODEL` | `qwen2.5:7b` | Classifier/reporter model |
| `CORRAL_LLM_API_KEY` | unset | For hosted endpoints |

`GET /metrics` (admin-only — the counter shape fingerprints which detectors fire) exposes events ingested, incidents created, sessions suspended, and flags fired by class.

---

## Verify It Yourself

```bash
corral selftest                           # 138 checks (139 with the optional langchain extra)
corral loadtest --agents 200              # fleet-scale check, no LLM needed
python3 dogfood.py                        # 14 scenarios against real LLM agents (requires Ollama)
DOGFOOD_SWARM_N=20 python3 dogfood.py     # S14 with a 20-agent swarm
```

The selftest covers the policy engine, resource extraction across every channel kind, verb-classification guards, token-forgery rejection, the kill switch, zero-trust communication, saturation self-healing, and a regression check for **every row in the review history above** — including the v1.0.4 round (scoped blocks, identity-required startup, kind-aware verbs, padding resistance, fingerprint coverage, closed admin surface, validated proposals, token-scoped benign list, server-side canaries).

---

## Status

**v1.0.4 — beta, not a production release.** Dogfooded against real LLM agents (14 scenarios, 5–20-agent swarm); load-tested to saturation with precision held at every tier. Four adversarial review rounds: three self-reviews (v0.5.x, the v1.0.3 rogue-agent mirror) and two external (v1.0.2, v1.0.4) — every fix regression-guarded, **138 selftest checks**. Hard boundary, unchanged: SQLite, single node — the auditability is the point; multi-host aggregation is the cloud roadmap.

### Changelog

| Version | What shipped |
|---|---|
| v0.1–v0.4 | Initial build: `GuardedAgent` SDK, collector (FastAPI + SQLite + embedded dashboard), persisted access graph, act-file-narrate-async defender, zero-trust CommPolicy, replay demo, dogfood suite |
| v0.5.x | First adversarial review, fixed: signature-bound args, scoped credentials, session tokens, synchronous enforcement, server-clock windows, canonical normalization, deep-scan extraction, identity binding, ingest limits, relay-laundering veto, halted-attempt forensics, deterministic classification |
| v0.6–v0.8 | Channel surface (`index`/`log`/`job` kinds, email + webhook egress, `wrap_mcp_tools`, `dormant_channel`); defender hardening (severity floor, payload fencing, ingest bounds); async SDK, SIEM webhook, session-IP binding, liveness; `baseline_deviation` |
| v1.0 / v1.0.1 | Production cut + docs; saturation hardening (retry/buffer self-heal, idempotent ingest, `corral loadtest`, S14 swarm) |
| v1.0.2 | External review, round 1: principal = agent_id, coordination identity, content-flow fingerprints, canaries, egress budgets, per-agent keys, learn mode, scoped campaign quarantine |
| v1.0.3 | Self red-team: agent-level quarantine, client-flags-are-hints, per-agent fingerprint store, asymmetric echo response, total egress budget, bare-host listing, per-IP registration rate, windowed cap, bounded proposals |
| v1.0.4 | External review, round 2: scoped blocks, required agent keys, two-segment version-aware identity, kind-aware verbs, ≥2-endpoint listing signal, padding-resistant queries, full fingerprint coverage, ingest-only fail-closed, validated admin-only proposals, token-scoped benign list, server-side canaries, WAL + defender resilience (150 agents: precision held) |


Free forever for local and single-team use. Cloud fleet management and compliance exports in development — join the discussion in issues.
