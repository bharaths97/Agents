from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from tooling import SemgrepRunner, SemgrepScanResult

logger = logging.getLogger(__name__)


class SemgrepEvidenceAgent:
    """
    Deterministic Semgrep evidence stage.
    This is an execution agent (not an LLM reasoning agent) that:
      1) indexes/selects rules
      2) executes Semgrep
      3) returns normalized findings for corroboration by 1b/1e
    """

    name = "SemgrepEvidenceAgent"

    def __init__(self, rules_root: Path, repo_path: Path):
        self.rules_root = rules_root
        self.repo_path = repo_path
        self.runner = SemgrepRunner(rules_root=rules_root, repo_path=repo_path)

    async def run(self, scan_result) -> SemgrepScanResult:
        logger.info(
            "[%s] Starting Semgrep evidence collection (rules_root=%s)",
            self.name,
            self.rules_root,
        )
        result = await asyncio.to_thread(self.runner.run, scan_result)
        if result.error:
            logger.warning("[%s] Completed with error: %s", self.name, result.error)
        else:
            logger.info(
                "[%s] Completed: %d findings from %d rules",
                self.name,
                len(result.findings),
                result.rules_selected,
            )
        return result
