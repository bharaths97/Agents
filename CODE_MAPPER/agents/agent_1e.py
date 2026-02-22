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
        call_graph_index=None,
    ):
        super().__init__(model=model, rag_store=rag_store)
        self.threat_model = threat_model
        self.repo_path = repo_path
        self.semgrep_findings_by_file = semgrep_findings_by_file or {}
        self.call_graph_index = call_graph_index
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
        call_graph_hints = self._extract_call_graph_hints(terrain.file)

        # --- Pass 1: Enumerate source-sink pairs ---
        pairs = await self._pass1_enumerate(
            terrain,
            source_code,
            threat_hints,
            semgrep_hints,
            call_graph_hints,
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
            call_graph_hints,
            rag_context,
        )

        # --- Phase 3 deterministic chain scoring / boundary enrichment ---
        pair_chain_index = self._build_pair_chain_index(pairs)
        output = self._apply_chain_scoring(output, pair_chain_index)

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
        call_graph_hints: str,
        rag_context: str,
    ) -> List[Dict[str, Any]]:
        """Pass 1: map source-sink flows structurally without assessing exploitability."""

        user_prompt = f"""PASS 1 — STRUCTURAL FLOW MAPPING for file: {terrain.file}

## Terrain Object
{json.dumps(terrain.model_dump(), indent=2)}

{threat_hints}
{semgrep_hints}
{call_graph_hints}

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
            pairs = raw.get("source_sink_pairs", [])
            return self._enrich_pairs_with_call_graph(terrain.file, pairs)
        except Exception as exc:
            logger.error(f"[{self.name}] Pass 1 failed for {terrain.file}: {exc}")
            return []

    async def _pass2_assess(
        self,
        terrain: TerrainObject,
        source_code: str,
        pairs: List[Dict[str, Any]],
        semgrep_hints: str,
        call_graph_hints: str,
        rag_context: str,
    ) -> Agent1eOutput:
        """Pass 2: assess exploitability for each enumerated pair."""

        user_prompt = f"""PASS 2 — VULNERABILITY ASSESSMENT for file: {terrain.file}

## Terrain Object
{json.dumps(terrain.model_dump(), indent=2)}

## Pass 1 Flow Map (source-sink pairs to assess)
{json.dumps(pairs, indent=2)}

{semgrep_hints}
{call_graph_hints}

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

    def _extract_call_graph_hints(self, file_path: str) -> str:
        if self.call_graph_index is None:
            return ""
        try:
            hints = self.call_graph_index.file_hints(file_path)
        except Exception as exc:
            logger.debug(f"[{self.name}] Call graph hints unavailable for {file_path}: {exc}")
            return ""

        direct_calls = hints.get("direct_cross_file_calls", [])
        call_chains = hints.get("call_chains", [])
        if not direct_calls and not call_chains:
            return ""

        payload = {
            "file": hints.get("file", file_path),
            "stats": hints.get("stats", {}),
            "direct_cross_file_calls": direct_calls[:10],
            "call_chains": call_chains[:10],
        }
        return (
            "\n## Phase 3 Cross-File Call Graph Hints\n"
            "Use these as structural hints only. Validate against actual source code.\n"
            f"{json.dumps(payload, indent=2)}\n"
        )

    def _enrich_pairs_with_call_graph(self, file_path: str, pairs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if self.call_graph_index is None or not pairs:
            return pairs
        try:
            hints = self.call_graph_index.file_hints(file_path)
        except Exception as exc:
            logger.debug(f"[{self.name}] Could not enrich with call graph for {file_path}: {exc}")
            return pairs

        call_chains = hints.get("call_chains", [])
        if not call_chains:
            return pairs

        enriched: List[Dict[str, Any]] = []
        for pair in pairs:
            if not isinstance(pair, dict):
                continue
            source_var = str(pair.get("source_variable", "")).strip()
            linked = self._match_call_chains(source_var, call_chains)
            pair["linked_call_chains"] = linked

            if linked:
                chain = linked[0]
                hops = chain.get("hops", [])
                tchain = list(pair.get("transformation_chain", []))
                step_num = len(tchain) + 1
                for hop in hops[:5]:
                    tchain.append(
                        {
                            "step": step_num,
                            "line": int(hop.get("call_line", 0) or 0),
                            "operation": (
                                f"cross-file call {hop.get('from_function', 'unknown')} -> "
                                f"{hop.get('to_function', 'unknown')}"
                            ),
                            "sanitization_applied": False,
                            "sanitization_notes": "Cross-file hop inferred from call graph",
                            "crosses_file_boundary": True,
                            "target_file": hop.get("to_file"),
                            "target_function": hop.get("to_function"),
                            "parameter_mapping": hop.get("parameter_mapping", {}),
                        }
                    )
                    step_num += 1
                pair["transformation_chain"] = tchain
            enriched.append(pair)
        return enriched

    @staticmethod
    def _match_call_chains(source_var: str, call_chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not call_chains:
            return []
        if not source_var:
            return call_chains[:2]

        matched = []
        for chain in call_chains:
            for hop in chain.get("hops", []):
                mapping = hop.get("parameter_mapping", {})
                values = {str(v) for v in mapping.values()}
                keys = {str(k) for k in mapping.keys()}
                if source_var in values or source_var in keys:
                    matched.append(chain)
                    break
        if matched:
            return matched[:3]
        return call_chains[:2]

    def _build_pair_chain_index(self, pairs: List[Dict[str, Any]]) -> Dict[tuple[str, str, str], Dict[str, Any]]:
        index: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        for pair in pairs:
            source_var = str(pair.get("source_variable", ""))
            linked = pair.get("linked_call_chains", []) or []
            if not linked:
                continue

            primary = linked[0]
            hops = primary.get("hops", [])
            chain_length = int(primary.get("chain_length", len(hops)) or len(hops))
            reaches = pair.get("reaches_sinks", []) or []
            for sink in reaches:
                sink_fn = str(sink.get("sink_fn", ""))
                sink_var = str(sink.get("sink_variable", ""))
                key = (source_var, sink_fn, sink_var)
                index[key] = {
                    "boundary_hops": hops,
                    "chain_length": chain_length,
                    "crosses_file_boundary": chain_length > 0 and any(
                        str(h.get("from_file", "")) != str(h.get("to_file", ""))
                        for h in hops
                    ),
                }
        return index

    def _apply_chain_scoring(
        self,
        output: Agent1eOutput,
        pair_chain_index: Dict[tuple[str, str, str], Dict[str, Any]],
    ) -> Agent1eOutput:
        if not output.taint_findings:
            return output

        updated = []
        for finding in output.taint_findings:
            source_var = str(finding.source.get("variable", ""))
            sink_fn = str(finding.sink.get("sink_fn", ""))
            sink_var = str(finding.sink.get("variable", ""))

            info = pair_chain_index.get((source_var, sink_fn, sink_var))
            if info is None:
                info = pair_chain_index.get((source_var, sink_fn, ""))

            if info is None:
                updated.append(finding)
                continue

            chain_length = int(info.get("chain_length", 0) or 0)
            crosses = bool(info.get("crosses_file_boundary", False))
            boundary_hops = info.get("boundary_hops", [])

            confidence = finding.confidence
            reasoning = list(finding.confidence_reasoning)
            if chain_length > 1:
                decay = min(0.30, 0.05 * (chain_length - 1))
                confidence = max(0.0, confidence - decay)
                reasoning.append(
                    f"Confidence decayed by {decay:.2f} due to cross-file chain length {chain_length}."
                )

            if self._has_semgrep_corroboration(output.file, finding.cwe, sink_fn):
                confidence = min(1.0, confidence + 0.03)
                reasoning.append("Semgrep corroboration matched file/CWE or sink context.")

            updated.append(
                finding.model_copy(
                    update={
                        "crosses_file_boundary": crosses,
                        "boundary_hops": boundary_hops,
                        "chain_length": chain_length if chain_length > 0 else None,
                        "confidence": round(confidence, 4),
                        "confidence_reasoning": reasoning,
                    }
                )
            )

        return Agent1eOutput(
            file=output.file,
            pass1_flow_map=output.pass1_flow_map,
            taint_findings=updated,
            conflict_resolutions=output.conflict_resolutions,
            clean_paths=output.clean_paths,
            low_confidence_observations=output.low_confidence_observations,
        )

    def _has_semgrep_corroboration(self, file_path: str, cwe: str, sink_fn: str) -> bool:
        hits = self.semgrep_findings_by_file.get(file_path, [])
        if not hits and self.repo_path:
            alt = str((self.repo_path / file_path).resolve()) if not Path(file_path).is_absolute() else file_path
            hits = self.semgrep_findings_by_file.get(alt, [])
        if not hits:
            return False

        normalized_cwe = (cwe or "").upper()
        sink_fn_l = (sink_fn or "").lower()
        for hit in hits:
            cwes = [str(item).upper() for item in hit.get("cwe", [])]
            if normalized_cwe and normalized_cwe in cwes:
                return True
            message = str(hit.get("message", "")).lower()
            if sink_fn_l and sink_fn_l in message:
                return True
        return False

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
