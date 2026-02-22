"""
Agent 1a — Context & Domain Reader

Stage: Terrain (Ring 0, runs in parallel with 1b and 1c)

Reads everything that is NOT application code and builds a domain model
that all downstream agents use as their interpretive lens.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import aiofiles

from .base import BaseAgent
from .code_scanner_prompts import AGENT_BASE_INSTRUCTIONS, AGENT_1A_DOMAIN_READER
from schemas.models import (
    Agent1aOutput, UserType, DeploymentContext,
)

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = AGENT_BASE_INSTRUCTIONS + "\n\n" + AGENT_1A_DOMAIN_READER


class Agent1a(BaseAgent):
    name = "Agent1a-ContextDomainReader"

    async def run(self, context_files: List[Path]) -> Agent1aOutput:
        """
        Read all context/non-code files and return a structured domain model.

        Args:
            context_files: Docs, configs, test files, CI/CD files — NOT source code.

        Returns:
            Agent1aOutput with full domain model for downstream agents.
        """
        logger.info(f"[{self.name}] Starting — {len(context_files)} context files")

        file_contents = await self._read_files(context_files)

        if not file_contents:
            logger.warning(f"[{self.name}] No readable context files — returning null domain model")
            return self._null_output()

        rag_context = await self.retrieve_references(
            "application domain classification data sensitivity security posture "
            "regulatory context HIPAA PCI-DSS GDPR deployment authentication"
        )

        user_prompt = self._build_user_prompt(file_contents, rag_context)

        raw = await self.call_llm(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.1,
        )

        output = Agent1aOutput(**raw)
        logger.info(
            f"[{self.name}] Complete — domain='{output.domain}', "
            f"risk_tier={output.domain_risk_tier}, "
            f"regulatory={output.regulatory_context}"
        )
        return output

    async def _read_files(self, files: List[Path]) -> List[dict]:
        """Read file contents, skipping unreadable files. Truncates very large files."""
        results = []
        for path in files:
            try:
                async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = await f.read()
                if len(content) > 12_000:
                    content = content[:12_000] + "\n\n[...file truncated for length...]"
                results.append({"path": str(path), "content": content})
            except Exception as exc:
                logger.debug(f"[{self.name}] Skipping {path}: {exc}")
        return results

    def _build_user_prompt(self, file_contents: List[dict], rag_context: str) -> str:
        sections = [
            f"=== FILE: {item['path']} ===\n{item['content']}\n"
            for item in file_contents
        ]
        files_block = "\n".join(sections)

        return f"""Analyze the following non-code files and produce the domain model JSON.

{rag_context}

## Files to Analyze

{files_block}

Output ONLY the JSON object. No preamble. No explanation.
"""

    @staticmethod
    def _null_output() -> Agent1aOutput:
        return Agent1aOutput(
            domain="Unknown — no documentation or configuration files found",
            domain_risk_tier="MEDIUM",
            domain_risk_reasoning="Cannot determine; no documentation present",
            regulatory_context=["NONE"],
            user_types=[
                UserType(
                    type="unknown",
                    trust_level="UNTRUSTED",
                    description="No documentation to determine user types",
                )
            ],
            data_handled=[],
            component_intent_map={},
            intended_security_posture="Cannot determine — no documentation available",
            deployment_context=DeploymentContext(
                environment="unknown",
                publicly_exposed=False,
                authentication_mechanism="unknown",
                notable_infrastructure=[],
            ),
            test_derived_assumptions=[],
            notable_developer_comments=[],
            flags=["No documentation found; all downstream analysis operates without domain context"],
        )
