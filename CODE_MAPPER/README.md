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
# Edit .env with your OPENAI_API_KEY
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
- Per-file taint analysis findings
- System-wide threat model
- Vulnerability severity and confidence scores

## Documentation

Detailed setup, configuration, architecture, and implementation guidance is in the [`docs/`](./docs/) folder.

Start with [`docs/README.md`](./docs/README.md) for navigation.
