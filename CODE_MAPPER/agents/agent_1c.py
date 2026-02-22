"""
Agent 1c — Data & Logging Classifier

Stage: Terrain (Ring 0, runs in parallel with 1a and 1b)

Classifies all significant data types and audits every logging call for
potential sensitive data exposure. Domain context from Agent 1a is passed in
to inform classification (e.g., user_id in a healthcare app is PHI).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import aiofiles

from .base import BaseAgent
from .code_scanner_prompts import AGENT_BASE_INSTRUCTIONS, AGENT_1C_DATA_CLASSIFIER
from schemas.models import Agent1cOutput, Agent1aOutput
from config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = AGENT_BASE_INSTRUCTIONS + "\n\n" + AGENT_1C_DATA_CLASSIFIER

MAX_FILE_CHARS = 20_000


class Agent1c(BaseAgent):
    name = "Agent1c-DataLoggingClassifier"

    async def run(
        self,
        code_files: List[Path],
        domain_output: Optional[Agent1aOutput] = None,
    ) -> Agent1cOutput:
        """
        Classify data types and audit logging across all source code files.

        Args:
            code_files: Application source files.
            domain_output: Agent 1a output (used to inform classification context).
                           May be None if 1a is still running — caller handles ordering.

        Returns:
            Agent1cOutput with data taxonomy and logging findings.
        """
        logger.info(f"[{self.name}] Starting — {len(code_files)} code files")

        domain_context = self._format_domain_context(domain_output)

        batch_size = settings.concurrent_file_workers
        all_taxonomy: Dict = {}
        all_log_findings: List = []

        for i in range(0, len(code_files), batch_size):
            batch = code_files[i : i + batch_size]
            result = await self._analyze_batch(batch, domain_context)
            all_taxonomy.update(result.data_taxonomy)
            all_log_findings.extend(result.logging_findings)

        output = Agent1cOutput(
            data_taxonomy=all_taxonomy,
            logging_findings=all_log_findings,
        )
        logger.info(
            f"[{self.name}] Complete — {len(all_taxonomy)} taxonomy entries, "
            f"{len(all_log_findings)} logging findings"
        )
        return output

    async def _analyze_batch(
        self, files: List[Path], domain_context: str
    ) -> Agent1cOutput:
        file_contents = await self._read_files(files)
        if not file_contents:
            return Agent1cOutput(data_taxonomy={}, logging_findings=[])

        rag_context = await self.retrieve_references(
            "PII PHI CREDENTIAL FINANCIAL data classification logging sensitive "
            "data exposure audit log redaction"
        )
        user_prompt = self._build_user_prompt(file_contents, domain_context, rag_context)

        try:
            raw = await self.call_llm(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
            )
            return Agent1cOutput(**raw)
        except Exception as exc:
            paths = [f["path"] for f in file_contents]
            logger.error(f"[{self.name}] Batch analysis failed for {paths}: {exc}")
            return Agent1cOutput(data_taxonomy={}, logging_findings=[])

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

    @staticmethod
    def _format_domain_context(domain_output: Optional[Agent1aOutput]) -> str:
        if domain_output is None:
            return "Domain context: Not yet available — classify conservatively."
        return (
            f"Domain: {domain_output.domain}\n"
            f"Risk Tier: {domain_output.domain_risk_tier}\n"
            f"Regulatory: {', '.join(domain_output.regulatory_context)}\n"
            f"Data Sensitivity: {domain_output.domain_risk_reasoning}\n"
            f"User Types: {[ut.type + ' (' + ut.trust_level + ')' for ut in domain_output.user_types]}"
        )

    def _build_user_prompt(
        self,
        file_contents: List[dict],
        domain_context: str,
        rag_context: str,
    ) -> str:
        sections = [
            f"=== FILE: {item['path']} ===\n{item['content']}\n"
            for item in file_contents
        ]
        files_block = "\n".join(sections)

        return f"""## Domain Context (from Agent 1a — use this to inform all classifications)

{domain_context}

{rag_context}

## Source Code Files to Analyze

{files_block}

Classify all significant data variables and audit all logging calls.
Output ONLY the JSON object. No preamble. No explanation.
"""
