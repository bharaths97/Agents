"""
Agent 1e — Taint Tracer

Stage: Trace (sequential, consumes streamed terrain from Agent 1d via asyncio.Queue)

Performs full taint analysis using two mandatory passes per file:
  Pass 1 — Structural flow mapping (enumerate, do not assess)
  Pass 2 — Vulnerability assessment (trace and evaluate each path)

Also resolves conflicts flagged by Agent 1d and documents clean paths.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from .base import BaseAgent
from .agent_1d import TERRAIN_DONE
from .code_scanner_prompts import AGENT_BASE_INSTRUCTIONS, AGENT_1E_TAINT_TRACER
from schemas.models import TerrainObject, Agent1eOutput, ThreatModel
from validation.adversarial import AdversarialVerifier
from validation.schema_validator import SchemaValidator

logger = logging.getLogger(__name__)

PASS1_SYSTEM_PROMPT = (
    AGENT_BASE_INSTRUCTIONS
    + "\n\n"
    + AGENT_1E_TAINT_TRACER
    + """

════════════════════════════════════════════════════════════════
CALL MODE: PASS 1 — STRUCTURAL FLOW MAPPING
════════════════════════════════════════════════════════════════

You are performing PASS 1 ONLY. Do NOT assess vulnerabilities. Do NOT emit taint findings.
Your only task: enumerate every source → sink path and map the transformation chain.

Output ONLY the pass1_flow_map JSON:
{
  "file": "string",
  "source_sink_pairs": [
    {
      "pair_id": "SSP-001",
      "source_variable": "string",
      "source_line": integer,
      "source_type": "string",
      "data_classification": "string",
      "transformation_chain": [
        {"step": 1, "line": 0, "operation": "string", "sanitization_applied": false, "sanitization_notes": ""}
      ],
      "reaches_sinks": [
        {"sink_variable": "string", "sink_line": 0, "sink_fn": "string", "sink_type": "string",
         "path_is_reachable": true, "reachability_notes": "string"}
      ],
      "linked_threat_scenario": "TS-001 or null"
    }
  ]
}

Order pairs by priority: highest-risk threat scenarios first, then by source sensitivity × sink danger.
"""
)

PASS2_SYSTEM_PROMPT = (
    AGENT_BASE_INSTRUCTIONS
    + "\n\n"
    + AGENT_1E_TAINT_TRACER
    + """

════════════════════════════════════════════════════════════════
CALL MODE: PASS 2 — VULNERABILITY ASSESSMENT
════════════════════════════════════════════════════════════════

You have the terrain object AND the Pass 1 flow map. Assess each source-sink pair.
Emit a taint finding ONLY for paths that are reachable AND unsanitized or
insufficiently sanitized. Document clean paths and low-confidence observations.

Output ONLY the full Agent 1e JSON object per the schema in your instructions above.
"""
)

MAX_FILE_CHARS = 24_000


class Agent1e(BaseAgent):
    name = "Agent1e-TaintTracer"

    def __init__(
        self,
        model=None,
        rag_store=None,
        threat_model: Optional[ThreatModel] = None,
        repo_path: Optional[Path] = None,
        semgrep_findings_by_file: Optional[Dict[str, List[dict]]] = None,
    ):
        super().__init__(model=model, rag_store=rag_store)
        self.threat_model = threat_model
        self.repo_path = repo_path
        self.semgrep_findings_by_file = semgrep_findings_by_file or {}
        self.adversarial = AdversarialVerifier(model=model, rag_store=rag_store)
        self.validator = SchemaValidator()

    async def run(self, terrain_queue: asyncio.Queue) -> List[Agent1eOutput]:
        """
        Consume terrain objects from the queue and perform taint tracing.

        Args:
            terrain_queue: asyncio.Queue streaming TerrainObjects from Agent 1d.
                           Ends with the TERRAIN_DONE sentinel.

        Returns:
            List of Agent1eOutput, one per analyzed file.
        """
        logger.info(f"[{self.name}] Listening for terrain objects")
        results: List[Agent1eOutput] = []

        while True:
            terrain = await terrain_queue.get()

            if terrain is TERRAIN_DONE:
                logger.info(f"[{self.name}] Stream complete — {len(results)} files traced")
                terrain_queue.task_done()
                break

            logger.info(f"[{self.name}] Tracing: {terrain.file}")
            output = await self._trace_file(terrain)
            results.append(output)
            terrain_queue.task_done()

        total_findings = sum(len(r.taint_findings) for r in results)
        logger.info(
            f"[{self.name}] Complete — {len(results)} files, "
            f"{total_findings} taint findings"
        )
        return results

    async def _trace_file(self, terrain: TerrainObject) -> Agent1eOutput:
        """Two-pass taint analysis for a single file."""

        if not terrain.sources or not terrain.sinks:
            logger.debug(f"[{self.name}] No sources or sinks in {terrain.file} — skipping")
            return Agent1eOutput(
                file=terrain.file,
                pass1_flow_map=[],
                taint_findings=[],
                conflict_resolutions=[],
                clean_paths=[],
                low_confidence_observations=[],
            )

        # Read the actual source file (Agent 1e has code access)
        source_code = await self._read_source_file(terrain.file)

        rag_context = await self.retrieve_references(
            f"SQL injection command injection path traversal XSS taint analysis "
            f"sanitization {terrain.domain_risk_tier} severity"
        )

        # Threat model hints for prioritization
        threat_hints = self._extract_threat_hints(terrain.file)
        semgrep_hints = self._extract_semgrep_hints(terrain.file)

        # --- Pass 1: Enumerate source-sink pairs ---
        pairs = await self._pass1_enumerate(
            terrain,
            source_code,
            threat_hints,
            semgrep_hints,
            rag_context,
        )

        if not pairs:
            return Agent1eOutput(
                file=terrain.file,
                pass1_flow_map=[],
                taint_findings=[],
                conflict_resolutions=[],
                clean_paths=[],
                low_confidence_observations=[],
            )

        # --- Pass 2: Assess exploitability ---
        output = await self._pass2_assess(
            terrain,
            source_code,
            pairs,
            semgrep_hints,
            rag_context,
        )

        # --- Adversarial verification for HIGH/CRITICAL findings ---
        output = await self._adversarial_pass(output)

        # --- Schema validation + anti-hallucination enforcement ---
        output = self.validator.validate_1e_output(output)

        return output

    async def _pass1_enumerate(
        self,
        terrain: TerrainObject,
        source_code: str,
        threat_hints: str,
        semgrep_hints: str,
        rag_context: str,
    ) -> List[Dict[str, Any]]:
        """Pass 1: map source-sink flows structurally without assessing exploitability."""

        user_prompt = f"""PASS 1 — STRUCTURAL FLOW MAPPING for file: {terrain.file}

## Terrain Object
{json.dumps(terrain.model_dump(), indent=2)}

{threat_hints}
{semgrep_hints}

## Actual Source Code
{source_code}

{rag_context}

Map every source → sink flow. Order by threat scenario rank then by risk.
Output ONLY the JSON object with source_sink_pairs array.
"""

        try:
            raw = await self.call_llm(
                system_prompt=PASS1_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.0,
            )
            return raw.get("source_sink_pairs", [])
        except Exception as exc:
            logger.error(f"[{self.name}] Pass 1 failed for {terrain.file}: {exc}")
            return []

    async def _pass2_assess(
        self,
        terrain: TerrainObject,
        source_code: str,
        pairs: List[Dict[str, Any]],
        semgrep_hints: str,
        rag_context: str,
    ) -> Agent1eOutput:
        """Pass 2: assess exploitability for each enumerated pair."""

        user_prompt = f"""PASS 2 — VULNERABILITY ASSESSMENT for file: {terrain.file}

## Terrain Object
{json.dumps(terrain.model_dump(), indent=2)}

## Pass 1 Flow Map (source-sink pairs to assess)
{json.dumps(pairs, indent=2)}

{semgrep_hints}

## Actual Source Code
{source_code}

{rag_context}

For each pair: assess reachability, sanitization, and exploitability.
Emit findings ONLY for reachable, unsanitized paths.
Document clean paths and conflict resolutions.
Output ONLY the full JSON object per the schema.
"""

        try:
            raw = await self.call_llm(
                system_prompt=PASS2_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
            )
            return Agent1eOutput(**raw)
        except Exception as exc:
            logger.error(f"[{self.name}] Pass 2 failed for {terrain.file}: {exc}")
            return Agent1eOutput(
                file=terrain.file,
                taint_findings=[],
                conflict_resolutions=[],
                clean_paths=[],
                low_confidence_observations=[],
            )

    async def _adversarial_pass(self, output: Agent1eOutput) -> Agent1eOutput:
        """Run adversarial verification on HIGH/CRITICAL findings."""
        verified_findings = []
        for finding in output.taint_findings:
            if finding.severity in ("HIGH", "CRITICAL") and finding.confidence > 0.5:
                finding = await self.adversarial.verify_taint_finding(finding)
            verified_findings.append(finding)
        return Agent1eOutput(
            file=output.file,
            pass1_flow_map=output.pass1_flow_map,
            taint_findings=verified_findings,
            conflict_resolutions=output.conflict_resolutions,
            clean_paths=output.clean_paths,
            low_confidence_observations=output.low_confidence_observations,
        )

    def _extract_threat_hints(self, file_path: str) -> str:
        """Pull relevant threat scenario hints from the threat model for this file."""
        if not self.threat_model or not self.threat_model.prioritized_threat_scenarios:
            return ""
        relevant = [
            s for s in self.threat_model.prioritized_threat_scenarios
            if any(file_path in hint or file_path.split("/")[-1] in hint
                   for hint in s.taint_paths_to_investigate)
            or s.risk_score in ("CRITICAL", "HIGH")
        ]
        if not relevant:
            return ""
        hints_json = json.dumps(
            [s.model_dump() for s in relevant[:5]], indent=2
        )
        return f"\n## Threat Model Hints (prioritize these taint paths)\n{hints_json}\n"

    def _extract_semgrep_hints(self, file_path: str) -> str:
        hits = self.semgrep_findings_by_file.get(file_path, [])
        if not hits and self.repo_path:
            relative = file_path
            if file_path.startswith(str(self.repo_path)):
                relative = file_path[len(str(self.repo_path)) :].lstrip("/")
            rel_path = str((self.repo_path / relative).resolve())
            hits = self.semgrep_findings_by_file.get(rel_path, [])

        if not hits:
            return ""
        payload = json.dumps(hits[:20], indent=2)
        return f"\n## Semgrep Corroboration Hints\n{payload}\n"

    async def _read_source_file(self, file_path: str) -> str:
        """Read the actual source file from disk."""
        try:
            target = Path(file_path)
            if not target.is_absolute() and self.repo_path:
                target = self.repo_path / file_path
            async with aiofiles.open(target, "r", encoding="utf-8", errors="replace") as f:
                content = await f.read()
            if len(content) > MAX_FILE_CHARS:
                content = content[:MAX_FILE_CHARS] + "\n\n[...truncated...]"
            return content
        except Exception as exc:
            logger.warning(f"[{self.name}] Could not read source for {file_path}: {exc}")
            return f"[Source code unavailable: {exc}]"
