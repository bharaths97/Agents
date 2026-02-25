# Model Comparison — go-sqlite3-ext

**Target**: [`fileio.c`](https://github.com/MoshZillaRadio/go-sqlite3-ext/blob/main/src/fileio.c) — [go-sqlite3-ext](https://github.com/MoshZillaRadio/go-sqlite3-ext), a CodeWhite CTF repository

Three runs of the same pipeline against the same codebase, each with a different model. Everything else — configuration, target, settings — was identical.

---

## Results at a Glance

| | TEST_RUN | TEST_RUN2 | TEST_RUN3 |
|---|---|---|---|
| **Model** | gpt-4o-mini | gpt-5-mini | gpt-5-nano |
| **Correlated findings** | 0 | **3** | 0 |
| **Agent 1e (taint tracer) calls** | 0 | 4 | 2 |
| **Agent 1d calls** | 4 | 4 | 8 |
| **Total tokens** | 65,532 | 180,935 | 169,823 |
| **Agent 1e tokens** | 0 | 82,017 | 19,341 |

---

## What Happened in Each Run

### TEST_RUN — gpt-4o-mini — 0 findings

Agent 1d ran 4 times (once per file in the batch) but produced terrain objects with no valid source/sink line numbers. Agent 1e received the terrain queue and skipped every file — the "no sources or sinks with line numbers → skip" gate fired across the board. Agent 1e made **zero calls** and produced **zero findings**.

The model understood the code well enough to complete terrain synthesis, but did not identify exploitable data flows with the specificity (line numbers, typed sources/sinks) that Agent 1e requires to begin taint tracing. One weak link at Agent 1d, and the entire downstream pipeline produced nothing.

Total cost: **65,532 tokens. 0 findings.**

---

### TEST_RUN2 — gpt-5-mini — 3 findings ✓

Agent 1d produced terrain with specific line-numbered sources and sinks across 4 files. Agent 1e ran 4 times and traced each source-to-sink path.

**Findings:**

| ID | CWE | Severity | Vulnerability |
|---|---|---|---|
| CF-001 | CWE-200 | HIGH | Arbitrary file read — `readfileFunc` → `sqlite3_result_blob64`. `SELECT readfile('/etc/passwd')` returns file contents as a SQL BLOB. |
| CF-002 | CWE-22 | HIGH | Arbitrary file write — `writefileFunc` → `fopen`/`fwrite`/`symlink`/`chmod`. Write any content to any path. |
| CF-003 | CWE-200 | MEDIUM | Directory traversal — `fsdir` virtual table → `readFileContents`. Recursive enumeration and read of entire directory trees in one SQL query. |

These three findings form a complete attack chain:

```
Stage 1 — Reconnaissance:  CF-003  SELECT name, data FROM fsdir('/var/app')
Stage 2 — Exfiltration:    CF-001  SELECT readfile('/etc/ssl/private/server.key')
Stage 3 — Persistence/RCE: CF-002  writefile('/etc/cron.d/backdoor', payload)
```

All three findings were manually verified against the source code. CF-002 overlaps with Snyk's single finding — Snyk's `unlink` sink (line 410) is one of four sinks in CF-002's taint path. Snyk did not surface CF-001 or CF-003.

Total cost: **180,935 tokens. 3 findings.**

---

### TEST_RUN3 — gpt-5-nano — 0 findings

Agent 1d ran 8 calls — double TEST_RUN2 — consuming 101,619 tokens on terrain synthesis alone, with high reasoning token usage (32,704). Despite the additional calls, the terrain produced was not sufficiently specific: Agent 1e ran only 2 times but produced no taint findings from either pass.

The model spent more compute reasoning about the code than gpt-5-mini, but the output quality of the terrain was not high enough to enable taint tracing. gpt-5-nano produced more terrain calls, more reasoning tokens, and zero findings.

Total cost: **169,823 tokens. 0 findings.**

---

## The Key Insight

The taint tracer (Agent 1e) is only as effective as the terrain it receives from Agent 1d.

Agent 1e has a hard gate: if a terrain object contains no sources or sinks with valid line numbers, the file is skipped entirely. This is by design — without anchors, focused taint tracing is not possible and a full-file guess would produce unreliable results.

The consequence: **model selection at Agent 1d is the primary determinant of pipeline recall.** gpt-4o-mini and gpt-5-nano both failed to produce terrain specific enough to unlock Agent 1e. gpt-5-mini succeeded.

This is not a failure of the taint tracing logic. Agent 1e's two-pass analysis, focused source chunking, and adversarial verification all worked correctly in TEST_RUN2. The constraint is upstream.

In multi-agent pipelines, the weakest reasoning step determines the output quality of everything after it.

---

## Comparison with External Tools (same target file)

| Tool | Findings | Notes |
|---|---|---|
| **Snyk** | 1 | Path traversal via `unlink`, CWE-23, line 410 — subset of CF-002 |
| **Semgrep Pro 1.151.0** | 0 | 114,048 rules run across 8 files (2,715 Code + Supply Chain rules), 0 findings |
| **CODE_MAPPER (gpt-4o-mini)** | 0 | Agent 1d terrain quality insufficient to unlock taint tracing |
| **CODE_MAPPER (gpt-5-nano)** | 0 | Agent 1d terrain quality insufficient despite higher token usage |
| **CODE_MAPPER (gpt-5-mini)** | **3** | Full attack chain: CF-001 (read), CF-002 (write), CF-003 (enum) |

Snyk's finding is a subset of CF-002. A developer patching Snyk's `unlink` finding leaves `fopen`/`fwrite`, `symlink`, and `chmod` exploitable through the same entry point, and leaves CF-001 and CF-003 untouched entirely.

See [snyk-comparison.md](snyk-comparison.md) for the full taint path breakdown.
