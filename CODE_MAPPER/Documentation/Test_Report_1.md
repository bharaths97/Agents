# CODE_MAPPER Security Report — go-sqlite3-ext

**Generated:** 2026-02-23
**Repository:** [go-sqlite3-ext](https://github.com/MoshZillaRadio/go-sqlite3-ext) (CodeWhite CTF)
**Model:** `gpt-5-mini`
**Domain:** C extension library providing SQLite UDFs for filesystem operations
**Risk Tier:** `LOW` (extension-only, not a standalone application)
**Correlated Findings:** 3

> The raw HTML report is also available: [Test_Report_1.html](Test_Report_1.html) (download and open locally to view rendered)

---

## Top Threat Scenarios

| Rank | ID | Risk | Scenario |
|---|---|---|---|
| 1 | TS-001 | HIGH | Native extension load leads to in-process code execution |
| 2 | TS-002 | HIGH | SQL functions exfiltrate sensitive file contents |
| 3 | TS-003 | MEDIUM | Arbitrary filesystem modification via `writefile` |

---

## Findings Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |

---

## CF-001 — HIGH — Arbitrary File Read (CWE-200)

**Vulnerability:** Arbitrary file read / information exposure — sensitive file contents returned to SQL caller
**Confidence:** 0.47 | **Source → Sink:** line 199 → line 177
**File:** `src/fileio.c`

### Taint Path

```
Line 199:  zName = (const char *)sqlite3_value_text(argv[0]);
             ↓  user-supplied path passed directly
Line 151:  in = sqlite3_fopen(zName, "rb");
             ↓  file opened at attacker-controlled path
Line 175:  if (nIn == (sqlite3_int64)fread(pBuf, 1, (size_t)nIn, in)) {
             ↓  file contents read into buffer
Line 177:  sqlite3_result_blob64(ctx, pBuf, nIn, sqlite3_free);
             ↑  SINK: contents returned as SQL BLOB result
```

### Exploit Scenario

An attacker able to execute SQL can call:

```sql
SELECT readfile('/etc/passwd');
SELECT readfile('/var/lib/app/secrets.json');
SELECT readfile('/root/.ssh/id_rsa');
```

The file contents are returned as a BLOB directly to the SQL caller. No path check anywhere in the chain.

### Remediation

Enforce an allowlist of permitted base directories and canonicalise the path before opening:

```c
char *real = realpath(zName, NULL);
if (real == NULL) {
    sqlite3_result_error(ctx, "invalid path", -1);
    return;
}
if (strncmp(real, ALLOWED_BASE, strlen(ALLOWED_BASE)) != 0) {
    sqlite3_free(real);
    sqlite3_result_error(ctx, "path not allowed", -1);
    return;
}
/* use real for sqlite3_fopen */
sqlite3_free(real);
```

Alternatively, remove `readfile()` from builds where arbitrary SQL is accepted, or require configuration to opt-in explicit trusted directories.

---

## CF-002 — HIGH — Arbitrary File Write / Path Traversal (CWE-22)

**Vulnerability:** Arbitrary file write / path control — insufficient path validation leading to arbitrary file creation and modification
**Confidence:** 0.47 | **Source → Sink:** line 552 → line 436
**File:** `src/fileio.c`

### Taint Path

```
Line 552:  zFile = (const char *)sqlite3_value_text(argv[0]);
             ↓  user-supplied path, no validation
Line 564:  res = writeFile(context, zFile, argv[1], mode, mtime);
             ↓  passes directly into writeFile()
Line 436:  FILE *out = sqlite3_fopen(zFile, "wb");
             ↑  SINK: arbitrary write target opened
Line 442:  sqlite3_int64 n = fwrite(z, 1, sqlite3_value_bytes(pData), out);
             ↑  SINK: SQL blob written to file at attacker-controlled path
Line 410:  if (symlink(zTo, zFile) < 0) return 1;
             ↑  SINK: symlink created at attacker-controlled path  ← Snyk's finding
Line 450:  if (rc == 0 && mode && chmod(zFile, mode & 0777)) { rc = 1; }
             ↑  SINK: permissions applied to attacker-controlled path
```

> **Note:** Snyk's single finding (`unlink` at line 410 via the symlink branch) is one of four sinks in this taint path. Patching `unlink` alone leaves `fopen`/`fwrite`, `symlink`, and `chmod` fully exploitable through the same entry point.

### Exploit Scenario

An attacker who can execute SQL can:

```sql
-- Write a persistent cron job
SELECT writefile('/etc/cron.d/evil', '* * * * * root /tmp/shell', 0100644);

-- Overwrite SSH authorized_keys
SELECT writefile('/root/.ssh/authorized_keys', '<attacker-pubkey>', 0100600);

-- Create a symlink to escalate file access
SELECT writefile('/tmp/link', X'', 0120777);  -- symlink mode
```

### Remediation

Validate and canonicalise the target path before any file operation:

```c
char *real = realpath(zFile, NULL);
if (real == NULL) {
    ctxErrorMsg(pCtx, "invalid path");
    return 1;
}
if (strncmp(real, ALLOWED_BASE, strlen(ALLOWED_BASE)) != 0) {
    sqlite3_free(real);
    ctxErrorMsg(pCtx, "path not allowed: %s", zFile);
    return 1;
}
/* use 'real' for fopen/chmod; disallow S_ISLNK creation unless explicitly allowed */
sqlite3_free(real);
```

Additionally, consider removing dangerous operations (symlink creation, arbitrary `chmod`/`utimes`) or restricting them to configuration-time whitelisted directories. Document that this extension must not be used in contexts accepting untrusted SQL.

---

## CF-003 — MEDIUM — Directory Traversal / Information Exposure (CWE-200)

**Vulnerability:** `fsdir` virtual table enumerates and returns filesystem metadata and file contents without restriction
**Confidence:** 0.47 | **Source → Sink:** line 823 → line 911
**File:** `src/fileio.c`

### Taint Path

```
Line 823:  pCur->zPath = sqlite3_mprintf("%s/%s", pLvl->zDir, pEntry->d_name);
             ↓  path built from attacker-supplied base directory + directory entries
Line 826:  if (fileLinkStat(pCur->zPath, &pCur->sStat)) { ... }
             ↓  stat used to classify each entry
Line 911:  readFileContents(ctx, pCur->zPath);
             ↑  SINK: file contents at every path in the tree returned to SQL caller
```

### Exploit Scenario

An attacker can point `fsdir` at any system directory and enumerate + read everything in one query:

```sql
-- Enumerate all files and read contents recursively
SELECT name, data FROM fsdir('/etc');
SELECT name, data FROM fsdir('/var/lib/app');
SELECT name, data FROM fsdir('/home');
```

This is reconnaissance and exfiltration in a single SQL statement — no filenames need to be known in advance.

### Remediation

Restrict `fsdir` to a configured allowlist of base directories and canonicalise constructed paths before use:

```c
char *real = realpath(pCur->zPath, NULL);
if (!real || strncmp(real, ALLOWED_BASE, strlen(ALLOWED_BASE)) != 0) {
    sqlite3_result_error(ctx, "path not allowed", -1);
    sqlite3_free(real);
    return;
}
/* then call readFileContents on real */
sqlite3_free(real);
```

Consider adding an opt-in configuration flag to enable `fsdir` only in trusted/admin contexts, and document the risks.

---

## STRIDE Threat Model Summary

| Dimension | Count |
|---|---|
| Assets identified | 4 |
| Trust boundaries | 2 |
| Attack surface entries | 4 |
| STRIDE entries | 6 |

---

## CTF Artifacts

No CTF flag artifacts detected in this run.

> **Note:** A CTF flag (`FLAG{RepoOfWrath#...}`) is present in `fileio.c` lines 486–487, split across two C comment lines and preceded by the Windows API constant `FILE_FLAG_BACKUP_SEMANTICS` on the same line. The detection prompt was not structured to identify multi-line flags with adjacent API constant name camouflage. This is a documented gap — see [model-comparison.md](model-comparison.md).

---

## Tool Comparison (same target)

| Tool | Findings |
|---|---|
| Snyk | 1 (subset of CF-002) |
| Semgrep Pro 1.151.0 (114,048 rules) | 0 |
| CODE_MAPPER gpt-4o-mini | 0 |
| CODE_MAPPER gpt-5-nano | 0 |
| **CODE_MAPPER gpt-5-mini** | **3** |

Full breakdown: [model-comparison.md](model-comparison.md) · [snyk-comparison.md](snyk-comparison.md)
