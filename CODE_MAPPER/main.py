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
from orchestrator.repo_resolver import RepoResolver
from reports import ReportGenerator

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CODE_MAPPER Taint Analyst Agent")
    repo_group = parser.add_mutually_exclusive_group(required=True)
    repo_group.add_argument(
        "--repo-path",
        type=Path,
        help="Path to the target repository to analyze",
    )
    repo_group.add_argument(
        "--repo-url",
        type=str,
        help="Remote Git URL to clone and analyze",
    )
    parser.add_argument(
        "--repo-branch",
        type=str,
        default="",
        help="Optional branch to clone when using --repo-url",
    )
    parser.add_argument(
        "--repo-commit",
        type=str,
        default="",
        help="Optional commit SHA to checkout when using --repo-url",
    )
    parser.add_argument(
        "--refresh-clone",
        action="store_true",
        default=False,
        help="Force re-clone even when a cached clone exists for --repo-url",
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
    parser.add_argument(
        "--debug-dump",
        action="store_true",
        default=False,
        help="Write per-agent and per-stage intermediate outputs to <output-dir>/debug/",
    )
    parser.add_argument(
        "--clone-timeout-sec",
        type=int,
        default=settings.repo_clone_timeout_sec,
        help="Timeout per git operation in seconds for --repo-url mode",
    )
    parser.add_argument(
        "--clone-max-attempts",
        type=int,
        default=settings.repo_clone_max_attempts,
        help="Max clone retries for --repo-url mode",
    )
    parser.add_argument(
        "--clone-depth",
        type=int,
        default=settings.repo_clone_depth,
        help="Shallow clone depth for --repo-url mode (0 disables shallow clone)",
    )
    return parser.parse_args()


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def _write_debug_dump(result: object, output_dir: Path, base_stem: str) -> Path:
    """Write per-agent and per-stage intermediate outputs to <output_dir>/debug/."""
    debug_dir = output_dir / "debug" / base_stem
    debug_dir.mkdir(parents=True, exist_ok=True)

    def dump(name: str, data: object) -> None:
        (debug_dir / name).write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Stage 0 — repo scan
    scan = result.scan  # type: ignore[attr-defined]
    dump("00_scan.json", {
        "code_files": [str(p) for p in scan.code_files],
        "context_files": [str(p) for p in scan.context_files],
        "unknown_files": [str(p) for p in scan.unknown_files],
        "detected_languages": scan.detected_languages,
        "detected_frameworks": scan.detected_frameworks,
        "detected_infra": scan.detected_infra,
        "manifests": [str(p) for p in scan.manifests],
    })

    # Stage 0 — Semgrep evidence
    dump("01_semgrep.json", result.semgrep)  # type: ignore[attr-defined]

    # Stage 1 — Ring 0 agents (run in parallel)
    dump("02_agent_1a.json", result.agent_1a)  # type: ignore[attr-defined]
    dump("03_agent_1b.json", result.agent_1b)  # type: ignore[attr-defined]
    dump("04_agent_1c.json", result.agent_1c)  # type: ignore[attr-defined]

    # Stage 2a — Agent 1d: threat model (terrain objects are consumed by 1e and not stored separately)
    dump("05_agent_1d_threat_model.json", result.threat_model)  # type: ignore[attr-defined]

    # Stage 2b — Agent 1e: per-file taint analysis
    results_dict = result.to_dict()  # type: ignore[attr-defined]
    agent_1e_outputs = results_dict.get("agent_1e", []) or []
    dump("06_agent_1e_taint.json", agent_1e_outputs)

    # Stage 3 — Phase 3 call graph and linked observations
    dump("07_call_graph.json", result.call_graph)  # type: ignore[attr-defined]
    dump("08_phase3_links.json", result.phase3_links)  # type: ignore[attr-defined]

    # Stage 4 — Phase 2 correlator output
    dump("09_correlated_findings.json", result.correlated_findings)  # type: ignore[attr-defined]

    # Stage 5 — CTF artifacts
    dump("10_ctf_artifacts.json", result.ctf_artifacts)  # type: ignore[attr-defined]
    dump("11_token_usage.json", result.token_usage)  # type: ignore[attr-defined]

    return debug_dir


async def run(args: argparse.Namespace) -> Dict[str, Path]:
    if not settings.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Add it to .env or pass it as an environment variable."
        )

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.repo_path and (args.repo_branch or args.repo_commit or args.refresh_clone):
        logger.warning(
            "--repo-branch/--repo-commit/--refresh-clone are ignored when --repo-path is used."
        )

    clone_cache_dir_setting = Path(settings.repo_clone_cache_dir)
    if clone_cache_dir_setting.is_absolute():
        clone_cache_dir = clone_cache_dir_setting
    else:
        clone_cache_dir = output_dir / clone_cache_dir_setting

    resolver = RepoResolver(
        cache_root=clone_cache_dir,
        clone_timeout_sec=args.clone_timeout_sec,
        clone_max_attempts=args.clone_max_attempts,
        clone_depth=args.clone_depth,
    )
    resolved_repo = await asyncio.to_thread(
        resolver.resolve,
        args.repo_path,
        args.repo_url,
        args.repo_branch,
        args.repo_commit,
        args.refresh_clone,
    )
    repo_path = resolved_repo.repo_path
    if resolved_repo.source == "cloned":
        logger.info(
            "Resolved target via clone: %s (reused_cache=%s)",
            repo_path,
            resolved_repo.reused_cache,
        )
    else:
        logger.info("Resolved target via local path: %s", repo_path)

    orchestrator = TaintAnalystOrchestrator(repo_path=repo_path, model=args.model)
    result = await orchestrator.run()

    filename = args.output_file.strip()
    if not filename:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"code_mapper_report_{timestamp}.json"

    output_path = output_dir / filename
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repo_path": str(repo_path),
        "repo_source": resolved_repo.source,
        "repo_input": args.repo_url if args.repo_url else str(args.repo_path.resolve()),
        "repo_clone_metadata": {
            "repo_url": resolved_repo.repo_url,
            "branch": resolved_repo.branch,
            "commit": resolved_repo.commit,
            "reused_cache": resolved_repo.reused_cache,
            "cache_dir": str(clone_cache_dir),
        }
        if resolved_repo.source == "cloned"
        else {},
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

    if args.debug_dump:
        debug_dir = _write_debug_dump(result, output_dir, output_path.stem)
        report_paths["debug"] = debug_dir

    return report_paths


def main() -> None:
    args = parse_args()
    configure_logging(args.log_level)
    report_paths = asyncio.run(run(args))
    print(f"Analysis complete. JSON report written to: {report_paths['json']}")
    print(f"Markdown report: {report_paths['markdown']}")
    print(f"HTML report: {report_paths['html']}")
    print(f"Remediation tickets: {report_paths['tickets']}")
    if "debug" in report_paths:
        print(f"Debug dumps: {report_paths['debug']}")


if __name__ == "__main__":
    main()
