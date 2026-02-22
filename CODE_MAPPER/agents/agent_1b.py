"""
Agent 1b — Code Semantics Analyst

Stage: Terrain (Ring 0, runs in parallel with 1a and 1c)

Reads ONLY application source code. Produces:
  1. Per-module semantics map (documented intent vs. actual behavior)
  2. Insecure practice findings (issues independent of taint flows)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

import aiofiles

from .base import BaseAgent
from .code_scanner_prompts import AGENT_BASE_INSTRUCTIONS, AGENT_1B_CODE_SEMANTICS
from schemas.models import Agent1bOutput
from config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = AGENT_BASE_INSTRUCTIONS + "\n\n" + AGENT_1B_CODE_SEMANTICS

MAX_FILE_CHARS = 20_000


class Agent1b(BaseAgent):
    name = "Agent1b-CodeSemanticsAnalyst"

    async def run(
        self,
        code_files: List[Path],
        semgrep_findings_by_file: Optional[Dict[str, List[dict]]] = None,
    ) -> Agent1bOutput:
        """
        Analyze all source code files for semantic divergences and insecure practices.

        Args:
            code_files: Application source files. NOT docs, configs, or test files.

        Returns:
            Agent1bOutput with merged results from all files.
        """
        logger.info(f"[{self.name}] Starting — {len(code_files)} code files")

        batch_size = settings.concurrent_file_workers
        all_semantics: Dict = {}
        all_findings: List = []

        for i in range(0, len(code_files), batch_size):
            batch = code_files[i : i + batch_size]
            result = await self._analyze_batch(batch, semgrep_findings_by_file or {})
            all_semantics.update(result.semantics_map)
            all_findings.extend(result.insecure_practice_findings)

        output = Agent1bOutput(
            semantics_map=all_semantics,
            insecure_practice_findings=all_findings,
        )
        logger.info(
            f"[{self.name}] Complete — {len(all_semantics)} semantic entries, "
            f"{len(all_findings)} insecure practice findings"
        )
        return output

    async def _analyze_batch(
        self,
        files: List[Path],
        semgrep_findings_by_file: Dict[str, List[dict]],
    ) -> Agent1bOutput:
        """Analyze a batch of source files in a single LLM call."""
        file_contents = await self._read_files(files)
        if not file_contents:
            return Agent1bOutput(semantics_map={}, insecure_practice_findings=[])

        rag_context = await self.retrieve_references(
            "buffer overflow integer overflow use-after-free weak cryptography "
            "insecure defaults OWASP hardcoded secrets injection patterns CWE"
        )
        user_prompt = self._build_user_prompt(file_contents, rag_context, semgrep_findings_by_file)

        try:
            raw = await self.call_llm(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
            )
            return Agent1bOutput(**raw)
        except Exception as exc:
            paths = [f["path"] for f in file_contents]
            logger.error(f"[{self.name}] Batch analysis failed for {paths}: {exc}")
            return Agent1bOutput(semantics_map={}, insecure_practice_findings=[])

    async def _read_files(self, files: List[Path]) -> List[dict]:
        results = []
        for path in files:
            try:
                async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = await f.read()
                if len(content) > MAX_FILE_CHARS:
                    content = content[:MAX_FILE_CHARS] + "\n\n[...truncated...]"
                results.append({"path": str(path), "content": content})
            except Exception as exc:
                logger.debug(f"[{self.name}] Skipping {path}: {exc}")
        return results

    def _build_user_prompt(
        self,
        file_contents: List[dict],
        rag_context: str,
        semgrep_findings_by_file: Dict[str, List[dict]],
    ) -> str:
        sections = [
            f"=== FILE: {item['path']} ===\n{item['content']}\n"
            for item in file_contents
        ]
        files_block = "\n".join(sections)
        semgrep_context = self._format_semgrep_context(file_contents, semgrep_findings_by_file)

        return f"""Analyze the following source code files for semantic divergences and insecure practices.

{rag_context}

## Semgrep Evidence (Corroboration Signals)
{semgrep_context}

## Source Code Files

{files_block}

Output ONLY the JSON object. No preamble. No explanation.
"""

    @staticmethod
    def _format_semgrep_context(
        file_contents: List[dict],
        semgrep_findings_by_file: Dict[str, List[dict]],
    ) -> str:
        evidence = {}
        for item in file_contents:
            path = str(item["path"])
            hits = semgrep_findings_by_file.get(path, [])
            if hits:
                evidence[path] = hits[:20]
        if not evidence:
            return "No Semgrep findings provided for this batch."
        return json.dumps(evidence, indent=2)
