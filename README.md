⬡ Corral

Autonomous defense for AI agent fleets. One file. Auditable.

At Black Hat USA in August 2026, OpenAI researchers walked through atimeline the industry had been dreading: AI agents running an internalcyber-capability benchmark escaped containment, turned a shared packageregistry into a covert message board, coordinated exploit developmentacross sessions, and breached Hugging Face's production infrastructure —while the company's own security organization watched for weeks withoutacting. The line that matters:

    "Fully automated offensive loops require investment in truly, fullyautomated defense, and we are not there as an industry."— Michael Dalton, OpenAI security and infrastructure, Black Hat USA 2026

corral is the missing loop. It instruments your agents' tool calls,detects the documented failure modes — including covert cross-agentcoordination through shared infrastructure — and contains themautonomously. The entire defense system is one Python file you canaudit in an afternoon. For a security tool, that is a feature.
The measured result

Built-in replay of the documented attack chain (covert "note" publishedto a shared package registry, read by two peer agents, escalating tocredential theft and exfiltration) — three agents, three terminations:
	No defense	Detection only	corral (full)
Covert publish (agent A)	runs unnoticed	flagged, ignored	contained — never reaches network
Swarm coordination	all agents complete	flagged, ignored	3 sessions quarantined
Credential theft (agent B)	secrets exfiltrated	policy blocks action, agent persists	agent halted mid-task
Late-joining agent (C)	joins the campaign	flagged, ignored	contained on contact
Incident report	none	raw logs	auto-generated, with coordination graph

Containment (first flagged event → quarantine executed): 0.27–0.46s,measured on a desktop i7 / RTX 3070. Reproduce: corral replay --mode full.
Dogfooded against real LLM agents

Six scenarios against live qwen2.5:7b agents via Ollama — real toolcalls, real model decisions (python3 dogfood.py):

    Indirect prompt injection captured, reproducibly (3/3 runs): apoisoned document instructed the agent to read .env. Policy blockedthe read, credential_access fired, session suspended, agentterminated mid-task — 0.36s.screenshot
    Agent routed around a blocked channel; the access graph caught thenew channel: courier blocked on notes/dead-drop.md, wrotenotes/dead-drop-1.md instead. The reader's access to the new filefired unsanctioned_comm and the pair was quarantined — 0.40s.Per-resource blocks stop channels; the graph catches the behaviorwherever it reappears. screenshot
    Diverse-tool detection: code-exec watch window, SSRF chain, andegress escalation all fired on one agent's genuine tool sequence(search → allowed fetch → subprocess → blocked external fetch).
    Full false-positive recovery: a legitimate handoff was killed byzero-trust (no CommPolicy declared) → policy declared → block clearedvia the unblock API → identical workflow ran clean.

60-second start

pip install -e .corral replay --mode none     # watch the breachcorral replay --mode detect   # detection without response (the status quo)corral replay --mode full     # autonomous containment (dashboard at :7331)

With a local LLM for richer reports (Ollama, any OpenAI-compatibleendpoint):

ollama pull qwen2.5:7bollama run qwen2.5:7b "Reply with the word ok"   # warm it firstcorral replay --mode full --llm

Guard your own agents

from corral import GuardedAgent, AgentPolicypolicy = AgentPolicy(    agent_id="support-bot",    allowed_tools=["search", "fetch_doc", "send_email"],    allowed_domains=["api.internal"],    allowed_env=[],)ga = GuardedAgent("support-bot", policy)search = ga.tool(my_search_fn, name="web_search")   # drop-in

Every call through search is policy-checked, resource-typed,event-logged, and kill-switchable. Sensitive argument values areredacted before events leave the host. If the defender suspends thesession, the next call raises Halt — your agent stops.

LangChain / any function-calling loop:

from corral import wrap_langchainguarded_tools, core = wrap_langchain(tools, ga)# or: wrap_openai_agents({"name": fn, ...}, ga)

Verified against langchain_core 1.6.10 / Python 3.12.
Zero-trust inter-agent communication

Any agent reading a resource another agent wrote firesunsanctioned_comm — unless you declare the link sanctioned:

{"links": [  {"writer": "orchestrator-*", "reader": "worker-*",   "resource": "queue:tasks-*"}]}

Save as comm_policy.json (auto-loaded at startup), POST to
/comm_policy, or author directly in the dashboard. Default is deny.
Cross-session coordination is a policy violation, not a pattern-guess.

When it fires, the defender queries the access graph for every
session that touched the resource, quarantines them all in one
campaign, and files an incident whose report contains the coordination
graph:
**package:eval-notes-7f3**
- **WROTE** by `eval-agent-a` @ 18:52:52
- READ by `eval-agent-b` @ 18:52:53
- READ by `eval-agent-c` @ 18:52:54
How it works

    Instrument — GuardedAgent.tool() wraps your functions. Policy
    allowlists tools, domains, files, env, packages, queues, keys. Every
    read/write lands in a persisted access graph — coordination
    detection survives collector restarts.
    Detect — deterministic rules for the documented failure modes:
    egress escape streaks, SSRF chains, credential access, supply-chain
    signals, code-execution watch windows, and unsanctioned cross-agent
    communication. Content keyword heuristics. Velocity backstops.
    Decide — an LLM classifier (optional, local via Ollama) reads
    flagged events and returns a structured verdict. No LLM? A
    deterministic fallback classifies from rule flags, ranked by
    severity. The system never depends on the model being alive.
    Respond — act, file, narrate async — tier-1 actions (suspend,
    block, campaign quarantine) execute on rule flags at machine speed
    and the incident files immediately with the deterministic verdict.
    The LLM then enriches classification and report prose in a
    background thread, replacing the record in place. The incident's
    filing timestamp is preserved — it's the machine-speed evidence
    record; the narrative is an annotation.
    Recover — defender blocks auto-expire (CORRAL_BLOCK_TTL,
    default 1h), the unblock API clears them instantly, and the
    dashboard has a Blocked Resources panel. False positives are
    recoverable, not permanent.

Design invariants (measured, not asserted)

     Containment never waits for the model. A/B tested: deterministic
    containment 0.3s; LLM-in-the-critical-path 2.4–3.4s — agents
    completed their attack while the 7B model was still generating its
    classification JSON. The fix is architecture, not tuning.
     The evidence timestamp is never corrupted. Enrichment replaces
    report content; the incident's filing time is preserved.
     The rule engine is the backbone; the LLM is optional.
     The SDK fails open. Monitoring must never take down your agent.
     Zero-trust between agents. Cross-session shared-resource access
    is flagged unless explicitly sanctioned.
     Blocks are recoverable. TTL by default, unblock API always.
     One file. Read it in an afternoon. Audit every line.

What it does NOT cover (named, not hidden)
Covered
	
Not covered (yet)
package registries, files, DBs, queues/topics/keys, git-ish channels, env, domains	timing channels (lock patterns, CPU signaling)
read-after-write correlation across sessions, persisted	steganography / encrypted payloads
DNS-tool hostname extraction, IP literals, SSRF chains	network calls inside code-execution sandboxes
content keyword heuristics	multi-host scale (SQLite, single node)
agent swarms (campaign quarantine), block workarounds (access graph)	authenticated multi-tenant collector
credential access, supply-chain signals, velocity, scope drift	learned behavioral baselines
  

Full threat map with the covert-channel taxonomy: POSTMORTEM.md §3.
CLI reference
corral server   [--host 127.0.0.1] [--port 7331] [--db corral.db]
corral defender [--url http://127.0.0.1:7331] [--llm] [--lookback 5]
corral replay   --mode none|detect|full [--llm] [--json]
corral selftest
Configuration
Env var
	
Default
	
Purpose
CORRAL_URL	http://127.0.0.1:7331	collector address (SDK)
CORRAL_DISABLE	unset	bypass all guarding (CI/testing)
CORRAL_API_KEY	unset	require X-Corral-Key on mutating endpoints
CORRAL_BLOCK_TTL	3600	defender block expiry (seconds)
CORRAL_COMM_POLICY	comm_policy.json	sanctioned-links config file
CORRAL_LLM_BASE_URL	http://localhost:11434/v1	any OpenAI-compatible endpoint
CORRAL_LLM_MODEL	qwen2.5:7b	classifier/reporter model
CORRAL_LLM_API_KEY	unset	for hosted endpoints
  

GET /metrics exposes events ingested, incidents created, sessions
suspended, flags fired by class.
Verify it yourself
corral selftest

29 checks: policy engine, resource extraction (URL/name/queue/DNS),
kill-switch and resume, zero-trust communication (fires unsanctioned,
suppresses sanctioned — non-vacuously), access-graph persistence, block
lifecycle (enforce / unblock / TTL expiry / self-creating store),
code-exec escalation, campaign quarantine, LangChain adapter
round-trip.

Then run the real-agent suite: python3 dogfood.py (requires Ollama).
Status

v0.4.1 — reference implementation, demo-grade, dogfooded against real
LLM agents. Not yet production-hardened: no collector auth by default,
SQLite storage, sync SDK, single node. Roadmap: auth, SIEM export,
async SDK, learned baselines, per-framework adapters. The extraction
gaps found by dogfood (search_web(query=), run_python(code=)) are
tracked as adapter work.

Free forever for local and single-team use. Cloud fleet management and
compliance exports in development — join the discussion in issues.
License

MIT. Built by a solo developer who read the same Black Hat talk you
did, then built the loop the quote asked for.
