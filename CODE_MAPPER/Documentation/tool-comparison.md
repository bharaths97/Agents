# Tool Comparison — Snyk vs Semgrep vs CODE_MAPPER

**Target**: [`fileio.c`](https://github.com/MoshZillaRadio/go-sqlite3-ext/blob/main/src/fileio.c) — [go-sqlite3-ext](https://github.com/MoshZillaRadio/go-sqlite3-ext), a CodeWhite CTF repository

Same file. Same vulnerabilities. Three tools.

---

## Results at a Glance

| | Snyk | Semgrep Pro | CODE_MAPPER (gpt-5-mini) |
|---|---|---|---|
| **Findings** | 1 | 0 | **3** |
| **Rules / approach** | Pattern matching + taint | 114,048 rules (2,715 Code + Supply Chain) | 5-agent LLM reasoning pipeline |
| **Functions covered** | `writefile()` only | None | `readfile()`, `writefile()`, `fsdir` |
| **Root cause identified** | No | N/A | Yes |
| **Attack chain** | Stage 3 tail only | None | Stages 1 → 2 → 3 complete |
| **Remediation scope** | Guard `unlink()` | N/A | Sanitise at all three entry points |
| **Deployment context** | Not addressed | N/A | Explicitly noted |
| **False positive risk** | Implicit (priority 600) | N/A | Explicit (0.47 confidence, MEDIUM FP risk) |

---

## Snyk

**Version:** Snyk Code (SAST)
**Finding:** 1 — Path traversal via `unlink`, CWE-23, priority 600

```
Source:  line 553 — zFile = sqlite3_value_text(argv[0])
Sink:    line 410 — unlink(zFile)
```

Snyk traced `zFile` backward from a single dangerous call (`unlink`) to its source. The finding is **correct** — this is a real vulnerability. However:

- It covers one of four dangerous sinks in the same function (`writefileFunc`)
- It has no visibility into `readfileFunc` (CF-001) or the `fsdir` virtual table (CF-003)
- Patching `unlink` at line 410 leaves `fopen` (line 436), `fwrite` (line 442), and `chmod` (line 450) exploitable through the same entry point at line 553

Snyk's finding is a **subset of CF-002**. The source (`argv[0]` at line 553) is identical. Snyk followed one branch; CODE_MAPPER traced all four.

---

## Semgrep Pro

**Version:** Semgrep Pro 1.151.0
**Finding:** 0
**Rules run:** 114,048 (2,715 Code rules including 56 C-specific + 222 multilang + 153 Go; 2,984 Supply Chain rules)
**Files scanned:** 8 (all files tracked by git)

Semgrep found nothing despite running over 100,000 rules.

**Why:** Semgrep's C ruleset matches known dangerous function signatures — `strcpy`, `gets`, `system`, `sprintf` without bounds, known injection sinks. The vulnerabilities in `fileio.c` don't match any of those patterns because:

- `sqlite3_fopen` and `sqlite3_result_blob64` are SQLite-specific wrappers, not standard libc functions that Semgrep's rules target
- The `fsdir` attack surface is a virtual table column accessor — there is no function call in its definition to pattern-match against
- The actual danger is the **absence** of a validation call (`realpath()`), not the presence of a known dangerous call — Semgrep's rules primarily match presence, not absence

This is the fundamental constraint of rule-based analysis: it can only find what its rules were written to find. When the vulnerability class is novel or the dangerous functions are domain-specific wrappers, rules don't fire.

---

## CODE_MAPPER (gpt-5-mini)

**Findings:** 3 — forming a complete attack chain

### CF-001 — Arbitrary File Read (CWE-200, HIGH)

```
Source:  line 199 — zName = sqlite3_value_text(argv[0])   [readfileFunc]
Sink:    line 151 — sqlite3_fopen(zName, "rb")
         line 177 — sqlite3_result_blob64(ctx, pBuf, nIn, sqlite3_free)
```

`SELECT readfile('/etc/passwd')` returns file contents as a SQL BLOB.
**Neither Snyk nor Semgrep had any visibility into this function.**

### CF-002 — Arbitrary File Write (CWE-22, HIGH)

```
Source:  line 553 — zFile = sqlite3_value_text(argv[0])   [writefileFunc]
Sink:    line 436 — sqlite3_fopen(zFile, "wb")             ← write
         line 442 — fwrite(z, 1, nData, out)               ← blob to disk
         line 410 — symlink(zTo, zFile)                    ← Snyk's finding
         line 450 — chmod(zFile, mode & 0777)              ← permissions
```

All four sinks traced from the same source. Snyk found the third sink only.

### CF-003 — Directory Enumeration + Read (CWE-200, MEDIUM)

```
Source:  line 823 — pCur->zPath (fsdir virtual table, path parameter)
Sink:    line 911 — fsdirColumn() → readFileContents()
```

`SELECT name, data FROM fsdir('/etc')` recursively reads an entire directory tree.
**`fsdir` is a virtual table — no dangerous function in its definition, so no backward trace is possible. This finding requires semantic understanding of what the virtual table does.**
**Neither Snyk nor Semgrep had any visibility into this attack surface.**

---

## Why the Gap Exists

The three tools represent three different analysis philosophies:

**Semgrep** — pattern matching. Fast, deterministic, zero false positives on its matched patterns. Misses anything not in its ruleset — domain-specific wrappers, absent validation, semantic design flaws.

**Snyk** — backward taint tracing from known dangerous sinks. Better than pattern matching for taint flows, but still anchored to a known-sink list. If the dangerous function isn't in Snyk's sink database, the trace never starts.

**CODE_MAPPER** — forward reasoning from intent. Starts by understanding what the code is supposed to do, maps where untrusted input enters, then reasons about what an attacker could do with that access. Not anchored to a known-sink list — the model derives the danger from context.

The `fsdir` finding illustrates this most clearly. A virtual table column accessor has no dangerous function to trace backward from. Snyk and Semgrep have nothing to start from. CODE_MAPPER identified it because it understood that a virtual table returning filesystem paths to a `readFileContents` call is semantically equivalent to an arbitrary file read — regardless of what functions are in the chain.

---

## The Shared Limitation

All three tools face the same constraint: static analysis cannot determine at code-reading time whether these functions are reachable by an untrusted caller in a given deployment.

The `readfile` and `writefile` functions are registered with `SQLITE_DIRECTONLY`, which prevents calls from VIEWs or TRIGGERs — a meaningful hardening measure. But it does not prevent a direct SQL statement from an untrusted connection from calling them.

Snyk reflects this with a priority score of 600 rather than maximum. CODE_MAPPER reflects it explicitly: all three findings carry confidence scores below 0.5 and MEDIUM false-positive risk, with the adversarial verifier noting that exploitability depends on deployment context.

The findings are real. Whether they're exploitable in a given deployment is a runtime question, not a static analysis question.

---

## Attack Chain (CODE_MAPPER only)

```
Stage 1 — Reconnaissance
  CF-003: SELECT name, data FROM fsdir('/var/app')
  → Enumerate all files, read contents, identify targets

Stage 2 — Exfiltration
  CF-001: SELECT readfile('/var/app/.env')
  → Extract credentials, keys, certificates

Stage 3 — Persistence / RCE
  CF-002: writefile('/etc/cron.d/backdoor', '* * * * * root /tmp/shell')
  → Write cron job, overwrite authorized_keys, deploy web shell
```

Snyk found the tail of Stage 3. Semgrep found nothing. CODE_MAPPER mapped all three stages from a single SQL entry point.

---

## Further Reading

- [Full taint path analysis — Snyk vs CODE_MAPPER](snyk-comparison.md)
- [Model comparison — how different LLMs performed on the same target](model-comparison.md)
- [Full security report — all findings with exploit scenarios and remediation](Test_Report_1.md)
