# CODE_MAPPER vs Snyk: A Technical Breakdown

**Target**: [`fileio.c`](https://github.com/MoshZillaRadio/go-sqlite3-ext/blob/main/src/fileio.c) — [go-sqlite3-ext](https://github.com/MoshZillaRadio/go-sqlite3-ext), a CodeWhite CTF repository

---

## The Results

| | Snyk | CODE_MAPPER |
|---|---|---|
| Findings | 1 | 3 |
| Functions covered | `writefile()` | `readfile()`, `writefile()`, `fsdir` |
| Root cause identified | No | Yes |
| Attack chain | Stage 3 tail only | Stages 1 → 2 → 3 complete |
| Remediation scope | Guard `unlink()` | Sanitise at all three entry points |

---

## What Snyk Found

Snyk identified one path traversal finding (CWE-23, priority 600):

```
Source:  line 553 — zFile = sqlite3_value_text(argv[0])
Sink:    line 410 — unlink(zFile)
```

An unsanitised user-supplied file path passed to `unlink()`. Correct — it's a real vulnerability.

---

## What CODE_MAPPER Found

CODE_MAPPER found three findings from the same file, each tracing a different source-to-sink path.

### CF-001 — Arbitrary File Read (CWE-200, HIGH)

```
Source:  line 199 — zName = sqlite3_value_text(argv[0])   [readfileFunc]
Sink:    line 151 — f = sqlite3_fopen(zName, "rb")
         line 177 — sqlite3_result_blob64(ctx, pBuf, nBuf, sqlite3_free)
```

**What this means**: `SELECT readfile('/etc/passwd')` returns the file's contents as a SQL BLOB. No path check, no allowlist, no canonicalisation anywhere in the chain. Works on any file the process has read access to — `/root/.ssh/id_rsa`, `/etc/shadow`, application secrets, private keys.

Snyk had no visibility into this function at all.

---

### CF-002 — Arbitrary File Write / Path Traversal (CWE-22, CRITICAL)

```
Source:  line 553 — zFile = sqlite3_value_text(argv[0])   [writefileFunc]
Sink:    line 436 — out = sqlite3_fopen(zFile, "wb")       ← arbitrary write
         line 442 — fwrite(z, 1, nData, out)               ← SQL blob written to disk
         line 410 — symlink(zTo, zFile)                    ← symlink creation  ← Snyk's finding
         line 450 — chmod(zFile, mode & 0777)              ← arbitrary permissions
```

**What this means**: `writefile('/etc/cron.d/backdoor', payload)` writes arbitrary content to any path. Beyond file writes: symlink creation lets an attacker redirect filesystem paths, `chmod` lets them change permissions on any file. The root cause is the absence of any validation before `writeFile()` is called — not any individual dangerous function within it.

Snyk found the `unlink` branch (line 410). CF-002 shows that patching `unlink` leaves `fopen`/`fwrite`, `symlink`, and `chmod` fully exploitable through the same entry point.

---

### CF-003 — Recursive Directory Enumeration + Read (CWE-200, HIGH)

```
Source:  line 823 — pCur->zPath (fsdir virtual table, path parameter)
Sink:    line 911 — fsdirColumn() → readFileContents()
```

**What this means**: `SELECT name, data FROM fsdir('/var/app')` recursively enumerates every file in a directory tree and returns each file's name and contents in a single SQL result set. This is reconnaissance and exfiltration in one query — an attacker can map an entire application's file structure and read every file in it without knowing any filenames in advance.

`fsdir` is a SQLite virtual table, not a function call. There is no dangerous function in its definition for a backward-tracing tool to start from. Finding this requires understanding what the virtual table does semantically, then tracing what data it exposes.

Snyk had no visibility into this attack surface.

---

## The Attack Chain

The three findings are not independent. They form a complete attack sequence:

```
Stage 1 — Reconnaissance
  CF-003: SELECT name, data FROM fsdir('/var/app')
  → Maps the entire filesystem, reads every file, identifies targets

Stage 2 — Exfiltration
  CF-001: SELECT readfile('/var/app/config/secrets.env')
  → Extracts specific high-value files: keys, credentials, certificates

Stage 3 — Persistence / RCE
  CF-002: writefile('/etc/cron.d/backdoor', '* * * * * root /tmp/shell')
  → Writes a cron job, overwrites an authorised_keys file, deploys a web shell
```

Snyk's finding — the `unlink` call — is at the tail of Stage 3. A developer fixing only that call leaves Stages 1, 2, and the rest of Stage 3 intact and fully exploitable.

---

## Root Cause

All three findings share the same root cause: **none of the three entry points — `readfileFunc`, `writefileFunc`, or the `fsdir` path parameter — perform any path validation before passing user input to filesystem operations**.

No `realpath()` call. No allowlist check. No canonicalisation.

Fixing this at the entry points — adding `realpath()` and validating against an allowlist before any filesystem operation — closes all three findings simultaneously. Snyk's remediation closes one sink in CF-002 while leaving the other three sinks and the other two entry points open.

---

## The Shared Limitation

Both tools face the same constraint that static analysis cannot resolve: they cannot determine at code-reading time whether these functions are reachable by an untrusted caller in a given deployment.

The `readfile` and `writefile` functions are registered with the `SQLITE_DIRECTONLY` flag, which prevents them from being called inside VIEWs or TRIGGERs — a meaningful hardening measure for certain injection vectors. But it does not prevent a direct SQL statement from an untrusted or compromised connection from calling them.

CODE_MAPPER reflects this uncertainty explicitly: all three findings carry a medium false-positive risk and confidence scores below 0.5, with the adversarial verifier noting that exploitability depends on deployment context. Snyk's priority score of 600 reflects the same uncertainty.

Neither tool is wrong. Both correctly identify real code-level paths. Deployment context is out of scope for static analysis.
