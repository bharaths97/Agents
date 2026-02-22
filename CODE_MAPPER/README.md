# CODE_MAPPER

A multi-agent taint-analysis system for automated security code review. Performs STRIDE threat modeling, data flow analysis, and vulnerability detection using a coordinated pipeline of specialized LLM agents.

## Quick Start

**Python:**
```bash
pip install -r requirements.txt
python main.py --repo-path /path/to/repo --output-dir ./output
```

**Docker:**
```bash
cp .env.example .env
# Edit .env with your OPENAI_API_KEY (and optional Phase 3 flags)
REPO_PATH=/path/to/repo docker compose up --build
```

## What You Need

- Python 3.11+ (or Docker)
- OpenAI API key
- Target source code repository

## Output

A JSON report with:
- Repository scan results (detected languages, frameworks, infrastructure)
- Optional Phase 3 call graph summary (`results.call_graph`) and fallback links (`results.phase3_links`)
- Optional Phase 3 linked-observation count in summary (`summary.phase3_linked_observations`)
- Per-file taint analysis findings
- System-wide threat model
- Vulnerability severity and confidence scores

## Phase 3 Controls

Cross-file tracing is available behind feature flags:
- `PHASE3_CROSS_FILE_ENABLED=true`
- `PHASE3_CALL_GRAPH_MAX_HOPS=5`
- `PHASE3_CALL_GRAPH_MAX_CHAINS_PER_FILE=20`

## Documentation

Detailed setup, configuration, architecture, and implementation guidance is in the [`docs/`](./docs/) folder.

Start with [`docs/README.md`](./docs/README.md) for navigation.
