# CODE_MAPPER

A multi-agent taint-analysis system for automated security code review. Performs STRIDE threat modeling, data flow analysis, and vulnerability detection using a coordinated pipeline of specialized LLM agents.

## Quick Start

**Python:**
```bash
pip install -r requirements.txt
python main.py --repo-path /path/to/repo --output-dir ./output
# Optional: write per-stage intermediate dumps
python main.py --repo-path /path/to/repo --output-dir ./output --debug-dump
# Or let CODE_MAPPER clone a remote repo directly
python main.py --repo-url https://github.com/org/repo.git --repo-branch main --output-dir ./output
```

**Docker:**
```bash
cp .env.example .env
# Edit .env with your OPENAI_API_KEY (and optional Phase 3 flags)
REPO_PATH=/path/to/repo docker compose up --build
# Or remote clone mode (no host repo mount required for target code)
REPO_URL=https://github.com/org/repo.git REPO_BRANCH=main docker compose up --build
# Optional: override output bind target
OUTPUT_DIR=~/code_mapper_results docker compose up --build
```

## What You Need

- Python 3.11+ (or Docker)
- OpenAI API key
- Target source code repository
- `git` installed when using `--repo-url` / `REPO_URL` clone mode

## Output

A JSON report with:
- Repository scan results (detected languages, frameworks, infrastructure)
- Correlated findings (`results.correlated_findings`) with deterministic dedup + ranking
- Per-agent LLM token usage (`results.token_usage.per_agent`) and totals (`results.token_usage.totals`)
- Optional Phase 3 call graph summary (`results.call_graph`) and fallback links (`results.phase3_links`)
- CTF artifact aggregation (`results.ctf_artifacts`)
- Optional Phase 3 linked-observation count in summary (`summary.phase3_linked_observations`)
- Correlated-finding count in summary (`summary.correlated_findings`)
- Per-file taint analysis findings
- System-wide threat model
- Vulnerability severity and confidence scores

Phase 6 report files are also generated next to the JSON output:
- `<report_name>.md` (human-readable Markdown report)
- `<report_name>.html` (styled HTML report)
- `<report_name>_tickets.json` (CRITICAL/HIGH remediation tickets)

Optional debug outputs:
- Pass `--debug-dump` to write per-stage intermediate outputs under:
  - `output/debug/<report_name>/00_scan.json` ... `11_token_usage.json`

## Phase 3 Controls

Cross-file tracing is available behind feature flags:
- `PHASE3_CROSS_FILE_ENABLED=true`
- `PHASE3_CALL_GRAPH_MAX_HOPS=5`
- `PHASE3_CALL_GRAPH_MAX_CHAINS_PER_FILE=20`

When enabled, Agent 1e links call chains only when chain-match scores pass a minimum threshold (with fallback only when exactly one candidate chain exists).

## Documentation

- [Architecture & how it works](./Documentation/architecture.md)
- [Model comparison — go-sqlite3-ext benchmark](./Documentation/model-comparison.md)
- [Snyk vs CODE_MAPPER — technical breakdown](./Documentation/snyk-comparison.md)
