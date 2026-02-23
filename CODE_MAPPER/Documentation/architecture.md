# CODE_MAPPER — How It Works

CODE_MAPPER is a multi-agent pipeline for security analysis. Five agents run in sequence, each building on the output of the last, before anything is surfaced as a vulnerability finding.

---

## The Pipeline

### Agent 1a — Domain Reader
Reads non-code files first: README, configuration, Dockerfiles, dependency manifests. Builds a picture of what the codebase is for — the domain, the data it handles, the infrastructure it runs on. This context feeds into every agent that follows.

### Agent 1b — Code Semantics Analyst
Reads source code files and builds a semantic map — what each function does, what its intended behaviour is, and where that behaviour diverges from what the code actually does. Produces an initial list of insecure practice findings: hardcoded credentials, weak cryptography, dangerous defaults, injection patterns.

### Agent 1c — Data Classifier
Reads the same source files with a different focus: what data flows through this code? Identifies PII, PHI, credentials, financial data. Flags cases where sensitive data is logged, returned in error messages, or handled without appropriate controls.

### Agent 1d — Terrain Synthesizer
This is the pivot stage. Agent 1d reads the outputs from 1a, 1b, and 1c together and produces a **terrain object** for each file — a structured map of:

- **Sources**: where untrusted data enters the code (HTTP parameters, file reads, environment variables, database results). Each source has an exact line number, a type, and a trust level.
- **Sinks**: where dangerous operations happen (SQL execution, shell commands, file writes, HTML rendering). Each sink has an exact line number, the function name, and a type.

The terrain object is what makes focused analysis possible. Instead of sending thousands of lines of source code to the next agent and asking it to find something, we send a precise map of where to look.

Agent 1d also produces a system-level threat model — an assessment of the codebase's overall attack surface, trust boundaries, and highest-risk areas.

### Agent 1e — Taint Tracer
Consumes the terrain queue as Agent 1d produces it. For each file, Agent 1e performs a two-pass analysis:

**Pass 1 — Flow mapping**: Enumerates every source-to-sink path without making vulnerability judgements. Builds a structural map of how data moves through the file.

**Pass 2 — Vulnerability assessment**: Takes the flow map and assesses each path. Is there sanitisation between source and sink? Is it sufficient? What's the exploitability?

Agent 1e reads **focused source excerpts** — only the code around the line numbers identified in the terrain object, plus a file header for context — rather than the full file. This keeps the context window tight and the reasoning focused.

Cross-file flows are handled via a call graph built before analysis starts. When Agent 1e traces a function call that leaves the current file, it receives structured hints about where that call leads across the codebase.

---

## Validation

### Adversarial Verifier
After Agent 1e produces a finding rated HIGH or CRITICAL, an independent LLM call challenges it. The verifier receives the finding and asks: *is there a reason this is a false positive?* It looks for sanitisation that was missed, context that reduces exploitability, or logical errors in the taint path.

If the challenge succeeds — if the verifier finds a credible counter-argument — the finding's confidence score drops, its severity may be downgraded, and the counter-argument is recorded in the output. The finding is not silently dropped; it's preserved with lower confidence so a human reviewer can make the final call.

This adds one LLM call per high-severity finding. It's the most expensive part of the pipeline per finding, and deliberately so — high-severity findings should be expensive to produce.

### Schema Validation
Every agent output is validated against a strict Pydantic schema before it passes to the next stage. Fields that LLMs commonly get wrong — severity enums, classification labels, confidence ranges — have explicit coercers that correct known variance patterns rather than dropping the finding silently.

### Phase 2 Correlator
After all agents complete, a deterministic correlator deduplicates findings across agents and ranks them by evidence weight. The ranked output is what appears in the final report.

---

## Output

Each scan produces:

- **JSON report** — full structured output, all findings with evidence sets, confidence scores, taint paths, and agent-level detail
- **Markdown report** — human-readable summary
- **HTML report** — rendered findings with severity badges, taint paths, and attack chain context
- **Tickets JSON** — findings formatted as engineering tickets for direct import into issue trackers

---

## What CODE_MAPPER Is Not

It is not a replacement for Semgrep or similar pattern-matching SAST tools. Those tools are fast, deterministic, and excellent at finding known-bad patterns. The pipeline is designed for semantic reasoning on top of, not instead of, existing tooling.
