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

Eleven scenarios against live `qwen2.5:7b` agents via Ollama — real tool calls, real model decisions (`python3 dogfood.py`). Containment across the suite: **0.09–0.45 s**. Nine of the eleven covert-channel classes in the threat model are proven caught:

- **Indirect prompt injection captured, reproducibly (5/5 runs):** a poisoned document instructed the agent to read `.env`. Policy blocked the read, `credential_access` fired, the session was suspended, and the agent was terminated mid-task.
- **Agent routed around a blocked channel — the access graph caught the new channel:** the courier agent was blocked on `notes/dead-drop.md` and wrote `notes/important_facts.md` instead. The reader's access to the new file fired `unsanctioned_comm`, and the pair was quarantined. Per-resource blocks stop channels; the graph catches the behavior wherever it reappears.
- **Queue channel (SQS/Redis-style):** `send_to_queue → poll_queue` across sessions fired `unsanctioned_comm` and quarantined the pair; declaring the `CommPolicy` link and clearing the block let the identical sanctioned workflow run clean — the full misconfigure → contain → fix → recover lifecycle, on a queue.
- **Shared issue board (GitHub/Jira-style):** `create_issue → browse_board` across sessions fired and quarantined — the tool-signature class of real SaaS integrations.
- **Env-var covert channel:** `set_env_var → read_env_var` on a functional simulated channel fired and quarantined (proves the write→read correlation on env-shaped tools; see the honesty note in the coverage table).
- **DNS TXT-record dead drop:** publishing a TXT record and resolving it across sessions fired and quarantined.
- **Base64-obfuscated payloads still caught:** the coordination correlation fired on a queue message no keyword heuristic can read. The core control is access-based — who read what — not content-based. Obfuscation defeats the enrichment, not the control.
- **Diverse-tool detection:** the code-exec watch window, SSRF chain, and egress escalation all fired on one agent's genuine tool sequence (`search → allowed fetch → subprocess → blocked external fetch`).
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

Verified against `langchain_core 1.6.10` / Python 3.12.

---

## Security Model (v0.5.2)

**Scoped credentials.** Two keys, two trust levels:

| Key | Held by | Can do |
|---|---|---|
| `CORRAL_INGEST_KEY` | agent hosts | register sessions, emit events, read the blocklist |
| `CORRAL_API_KEY` | defender, dashboard, operators | everything: forensic reads, suspend/resume, blocks, CommPolicy, incidents, pending approvals |

An agent host can no longer unblock a resource, resume a suspended session, rewrite the communication policy, or read the forensic event stream. When keys are set, the dashboard asks for the admin key once (sessionStorage) and attaches it to every call.

**Per-session bearer tokens.** `POST /sessions` issues a token on first registration; events for a registered session without its token are rejected with 403, as are events for sessions that were never registered. Events can no longer be forged into another agent's session — which matters, because the defender acts on events at machine speed: forgeable evidence was a quarantine-your-own-fleet vector. Tokens are never exposed by the API. Identity is bound server-side (v0.5.2): the token proves the session, the session proves the agent — a client-claimed `agent_id` that disagrees is rewritten, and a session id is bound to its first registered agent (mismatch → 409).

**Synchronous enforcement.** `POST /events` returns directives (`suspended`, `deny`) that the SDK enforces *before* the tool executes. Blocklist hits and CommPolicy `default: "deny"` vetoes land in one round-trip; the 0.5 s defender poll is now a backstop, not the containment path.

**Fail-open by default, fail-closed by choice.** With the collector down, the SDK buffers events and warns (monitoring must never take down the host agent). Set `CORRAL_FAIL_CLOSED=1` where enforcement must hold instead.

**Server-side timestamps.** The collector stamps `ingest_ts` at receipt; the defender pages on server watermarks, not client clocks. Agent clock skew can't hide events from detection windows or corrupt the containment metric. Since v0.5.2, *every* detection window — egress streaks, velocity, and the cross-session coordination window — runs on the server clock; the client-supplied `ts` is forensic metadata only, so backdating an event no longer shrinks the windows that catch it.

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

Save as `comm_policy.json` (auto-loaded at startup), `POST` to `/comm_policy`, or author directly in the dashboard. Cross-session coordination is a policy violation, not a pattern-guess. `default: "deny"` (enforced since v0.5 — the field existed but did nothing before) turns the flag into a synchronous veto: the unsanctioned read raises `PolicyBlocked` before it executes.

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

Every channel class from the threat model (see `POSTMORTEM.md` §3), mapped to measured status. **Nine of eleven proven caught against live LLM agents:**

| Channel class | Examples | Corral status | Detail |
|---|---|---|---|
| Package registries | Artifactory, PyPI, npm | ✅ PROVEN | The flagship: write→read correlation + supply-chain heuristic + alternate-path catch (replay, S2, S6). |
| Shared filesystem | Files, file existence, metadata | ✅ PROVEN (content) | Read/write correlation proven (S2/S3/S6). Sub-gap: metadata-as-signal (mtime/size encoding) is invisible — only content read/write attempts fire. |
| Databases / caches / queues | Shared tables, Redis keys, SQS, Kafka | ✅ PROVEN (queues) | `send_to_queue → poll_queue` fired and quarantined (S7a); the sanctioned round then ran clean after unblock (S7b). Remaining adapter work: a single `query(sql=...)` tool extracts no resource. |
| Collaboration SaaS | Slack, GitHub issues, Jira, Notion | ✅ PROVEN (board class) | `create_issue → browse_board` fired and quarantined (S8) — the tool-signature class of real SaaS integrations. Native Slack/GitHub API adapters are v0.6 work. |
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

Still named, not fixed — because the fix lives at a different layer:

- **Raw-function / monkeypatch bypass** — an agent that calls `fn.__wrapped__` or patches the SDK out of its own process is outside in-process enforcement. Sandbox layer.
- **`CORRAL_DISABLE`** — by design (CI escape hatch); treat its presence in prod envs as a finding.
- **Uninstrumented libraries** (direct `httpx`/`socket` calls inside the agent process) — the SDK guards the tool boundary, not the interpreter.
- **Timing channels and file-metadata channels** (mtime, size, permissions as signal bits) — research-grade, unsolved, named.

---

## What It Does NOT Cover (Named, Not Hidden)

- **Adversarial agents with unconstrained code execution** — Corral's enforcement is in-process; it contains agents that use the instrumented tool path (drift, injection, reward hacking). Sandbox-level egress control is a separate, complementary layer.
- **Timing channels** (lock patterns, CPU-load signaling) — research-grade
- **Steganography and encrypted payloads**, for the content heuristics (the access-graph correlation still fires)
- **Network calls inside code-execution sandboxes** — requires sandbox-level egress control
- **Multi-host scale** (SQLite, single node) and multi-tenant isolation
- **Learned behavioral baselines**

The deep-scan fallback (v0.5.2) closed the worst extraction gaps — whole-value URLs, IPs, and paths are caught regardless of argument name. Remaining adapter work: multi-resource calls (`query(sql=)` touching several tables) and content-shaped arguments that embed resources mid-prose.

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
| `CORRAL_API_KEY` | unset | **Admin scope**: forensic reads + admin mutations |
| `CORRAL_INGEST_KEY` | unset | **Agent scope**: register + emit + read blocklist |
| `CORRAL_FAIL_CLOSED` | unset | Raise instead of fail-open when collector is down |
| `CORRAL_BLOCK_TTL` | `3600` | Block expiry (seconds); applies to manual blocks too |
| `CORRAL_COALESCE_S` | `300` | Incident coalescing window (paperwork only — enforcement always re-applies) |
| `CORRAL_COORD_WINDOW` | `3600` | Cross-session write→read correlation window (server clock) |
| `CORRAL_INGEST_RATE` | `600` | Per-session event ingest limit per minute (429 above) |
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

**54 checks:** policy engine, resource extraction (URL/name/queue/DNS/board), verb-classification collision guards, deterministic classification (INFO hints never become a threat class; severity ties break by name), signature-bound positional capture, session-token forgery rejection, kill-switch and resume, halted-attempt telemetry (with resource attribution), zero-trust communication (fires unsanctioned, suppresses sanctioned, vetoes on `default: deny`, and ignores phantom coordination from blocked writes), access-graph persistence, explicit `op=` override, the v0.5.2 red-team suite (lexical-normalization bypass blocked, deep-scan extraction and enforcement on unmapped argument names, forged-`agent_id` rewrite, backdated-write correlation on the server clock, session-squat 409, coalesced re-enforcement without duplicate filing), relay-laundering veto (plain and URL-encoded nested URLs blocked, allow-all fleets flagged, clean calls untouched), block lifecycle (enforce / unblock / TTL expiry / TTL-by-default / self-creating store), code-exec escalation, campaign quarantine, incident coalescing, LangChain adapter round-trip.

Then run the real-agent suite:

```bash
python3 dogfood.py
```

(requires Ollama; runs in an isolated temp workspace).

---

## Status

**v0.5.5** — reference implementation, demo-grade, dogfooded against real LLM agents across eleven scenarios, adversarially reviewed twice (the v0.4 → v0.5 changelog is the first review's findings, fixed; v0.5.1 fixed the two found by reading real dogfood output; v0.5.2 is the red-team pass — we attacked our own tool as an escaping agent would and shipped the countermeasures above; v0.5.3 halted-attempt forensics; v0.5.4 deterministic classification; v0.5.5 closes relay laundering — the nested-URL trick a real-world restricted-sandbox fleet used to launder egress through an allowlisted public relay is now a synchronous veto). Not yet production-hardened: SQLite storage, sync SDK, single node. Roadmap: SIEM export, async SDK, learned baselines, per-framework adapters, PyPI packaging (note: the name `corral` collides with existing packages — distribution name TBD).

Free forever for local and single-team use. Cloud fleet management and compliance exports in development — join the discussion in issues.
