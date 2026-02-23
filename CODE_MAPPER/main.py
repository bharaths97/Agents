from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from config import settings
from orchestrator import TaintAnalystOrchestrator
from reports import ReportGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CODE_MAPPER Taint Analyst Agent")
    parser.add_argument(
        "--repo-path",
        type=Path,
        required=True,
        help="Path to the target repository to analyze",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory where analysis JSON output will be written",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="",
        help="Optional explicit filename for the JSON report",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=settings.openai_model,
        help="OpenAI chat model for agent reasoning",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=settings.log_level,
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    return parser.parse_args()


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


async def run(args: argparse.Namespace) -> Dict[str, Path]:
    repo_path = args.repo_path.resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise FileNotFoundError(f"Repo path does not exist or is not a directory: {repo_path}")

    if not settings.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Add it to .env or pass it as an environment variable."
        )

    orchestrator = TaintAnalystOrchestrator(repo_path=repo_path, model=args.model)
    result = await orchestrator.run()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = args.output_file.strip()
    if not filename:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"code_mapper_report_{timestamp}.json"

    output_path = output_dir / filename
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repo_path": str(repo_path),
        "model": args.model,
        "summary": result.summary,
        "results": result.to_dict(),
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    report_generator = ReportGenerator()
    report_paths = report_generator.generate_all(
        payload=payload,
        output_dir=output_dir,
        base_stem=output_path.stem,
    )
    report_paths["json"] = output_path
    return report_paths


def main() -> None:
    args = parse_args()
    configure_logging(args.log_level)
    report_paths = asyncio.run(run(args))
    print(f"Analysis complete. JSON report written to: {report_paths['json']}")
    print(f"Markdown report: {report_paths['markdown']}")
    print(f"HTML report: {report_paths['html']}")
    print(f"Remediation tickets: {report_paths['tickets']}")


if __name__ == "__main__":
    main()
