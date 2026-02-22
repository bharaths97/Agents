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
from schemas.models import Agent1eOutput, FlowMapEntry, TerrainObject, ThreatModel, TransformationStep
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
MAX_STRUCTURED_CHAIN_MATCHES = 4
CHAIN_CONFIDENCE_DECAY_PER_HOP = 0.04
CHAIN_CONFIDENCE_DECAY_CAP = 0.35


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
        output = self._apply_chain_scoring(output, pairs, pair_chain_index)

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
            if not isinstance(pairs, list):
                pairs = []
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
            source_line = self._safe_int(pair.get("source_line"))
            linked = self._select_call_chains_for_pair(source_var, source_line, call_chains)
            pair["linked_call_chains"] = linked

            transformation_chain = list(pair.get("transformation_chain", []))
            updated_chain, added_steps = self._append_cross_file_steps(transformation_chain, linked)
            pair["transformation_chain"] = updated_chain
            pair["phase3_cross_file_summary"] = {
                "linked_chain_count": len(linked),
                "cross_file_steps_added": added_steps,
                "max_chain_length": max(
                    [self._safe_int(item.get("chain_length")) for item in linked] or [0]
                ),
            }
            enriched.append(pair)
        return enriched

    def _select_call_chains_for_pair(
        self,
        source_var: str,
        source_line: int,
        call_chains: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not call_chains:
            return []

        scored: List[tuple[int, int, Dict[str, Any]]] = []
        for chain in call_chains:
            score = self._chain_match_score(source_var, source_line, chain)
            chain_len = self._safe_int(chain.get("chain_length"), default=0)
            scored.append((score, chain_len, chain))

        scored.sort(key=lambda item: (-item[0], -item[1]))
        selected: List[Dict[str, Any]] = []
        for score, _, chain in scored:
            if not selected:
                selected.append(chain)
                continue
            if score <= 0 and len(selected) >= 2:
                break
            selected.append(chain)
            if len(selected) >= MAX_STRUCTURED_CHAIN_MATCHES:
                break
        return selected

    def _chain_match_score(self, source_var: str, source_line: int, chain: Dict[str, Any]) -> int:
        score = 0
        normalized_source = self._normalize_symbol(source_var)
        hops = chain.get("hops", []) or []

        if normalized_source:
            for hop in hops:
                mapping = hop.get("parameter_mapping", {}) or {}
                values = {self._normalize_symbol(v) for v in mapping.values()}
                keys = {self._normalize_symbol(k) for k in mapping.keys()}
                if normalized_source in values or normalized_source in keys:
                    score += 8
                    break

        if source_line > 0 and hops:
            first_call_line = self._safe_int(hops[0].get("call_line"), default=0)
            if first_call_line > 0:
                line_distance = abs(first_call_line - source_line)
                if line_distance <= 5:
                    score += 4
                elif line_distance <= 15:
                    score += 2

        chain_length = self._safe_int(chain.get("chain_length"), default=len(hops))
        if chain_length >= 2:
            score += 1
        return score

    def _append_cross_file_steps(
        self,
        transformation_chain: List[Dict[str, Any]],
        linked_chains: List[Dict[str, Any]],
    ) -> tuple[List[Dict[str, Any]], int]:
        if not linked_chains:
            return transformation_chain, 0

        updated_chain = list(transformation_chain)
        existing_hops = {
            (
                self._safe_int(step.get("line"), default=0),
                str(step.get("target_file", "")),
                str(step.get("target_function", "")),
            )
            for step in updated_chain
            if isinstance(step, dict) and step.get("crosses_file_boundary")
        }

        added = 0
        for chain in linked_chains[:MAX_STRUCTURED_CHAIN_MATCHES]:
            hops = chain.get("hops", []) or []
            for hop in hops:
                hop_key = (
                    self._safe_int(hop.get("call_line"), default=0),
                    str(hop.get("to_file", "")),
                    str(hop.get("to_function", "")),
                )
                if hop_key in existing_hops:
                    continue
                existing_hops.add(hop_key)
                updated_chain.append(
                    {
                        "step": 0,
                        "line": self._safe_int(hop.get("call_line"), default=0),
                        "operation": (
                            f"cross-file call {hop.get('from_function', 'unknown')} -> "
                            f"{hop.get('to_function', 'unknown')}"
                        ),
                        "sanitization_applied": False,
                        "sanitization_notes": "Cross-file hop inferred from call graph",
                        "crosses_file_boundary": True,
                        "target_file": hop.get("to_file"),
                        "target_function": hop.get("to_function"),
                        "parameter_mapping": dict(hop.get("parameter_mapping", {}) or {}),
                    }
                )
                added += 1

        for idx, step in enumerate(updated_chain, start=1):
            if isinstance(step, dict):
                step["step"] = idx
        return updated_chain, added

    def _build_pair_chain_index(self, pairs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        index: Dict[str, Dict[str, Any]] = {}
        for pair in pairs:
            source_var = str(pair.get("source_variable", ""))
            source_line = self._safe_int(pair.get("source_line"), default=0)
            linked = pair.get("linked_call_chains", []) or []
            if not linked:
                continue

            primary = linked[0]
            hops = list(primary.get("hops", []) or [])
            if not hops:
                continue

            chain_length = self._safe_int(primary.get("chain_length"), default=len(hops))
            cross_file_hops = [
                hop for hop in hops if str(hop.get("from_file", "")) != str(hop.get("to_file", ""))
            ]
            if not cross_file_hops:
                continue

            mapped_hops = sum(1 for hop in hops if hop.get("parameter_mapping"))
            mapping_ratio = mapped_hops / max(1, len(hops))
            info = {
                "source_variable": source_var,
                "source_line": source_line,
                "boundary_hops": hops,
                "chain_length": chain_length,
                "cross_file_hops": len(cross_file_hops),
                "mapping_ratio": mapping_ratio,
                "crosses_file_boundary": True,
            }

            reaches = pair.get("reaches_sinks", []) or []
            if not reaches:
                for lookup in self._pair_lookup_keys(source_var, "", "", 0):
                    existing = index.get(lookup)
                    if existing is None or info["chain_length"] > existing["chain_length"]:
                        index[lookup] = info
                continue

            for sink in reaches:
                sink_fn = str(sink.get("sink_fn", ""))
                sink_var = str(sink.get("sink_variable", ""))
                sink_line = self._safe_int(
                    sink.get("sink_line", sink.get("line", 0)),
                    default=0,
                )
                for lookup in self._pair_lookup_keys(source_var, sink_fn, sink_var, sink_line):
                    existing = index.get(lookup)
                    if existing is None or info["chain_length"] > existing["chain_length"]:
                        index[lookup] = info
        return index

    @classmethod
    def _pair_lookup_keys(
        cls,
        source_var: str,
        sink_fn: str,
        sink_var: str,
        sink_line: int,
    ) -> List[str]:
        normalized_source = cls._normalize_symbol(source_var)
        normalized_sink_fn = cls._normalize_symbol(sink_fn)
        normalized_sink_var = cls._normalize_symbol(sink_var)
        line = sink_line if sink_line > 0 else 0
        return [
            f"{normalized_source}|{normalized_sink_fn}|{normalized_sink_var}|{line}",
            f"{normalized_source}|{normalized_sink_fn}|{normalized_sink_var}|0",
            f"{normalized_source}|{normalized_sink_fn}||{line}",
            f"{normalized_source}|{normalized_sink_fn}||0",
            f"{normalized_source}|||0",
        ]

    def _lookup_chain_info(self, pair_chain_index: Dict[str, Dict[str, Any]], finding) -> Optional[Dict[str, Any]]:
        source_var = str(finding.source.get("variable", ""))
        sink_fn = str(finding.sink.get("sink_fn", ""))
        sink_var = str(finding.sink.get("variable", ""))
        sink_line = self._safe_int(
            finding.sink.get("line", finding.sink.get("sink_line", 0)),
            default=0,
        )
        for lookup in self._pair_lookup_keys(source_var, sink_fn, sink_var, sink_line):
            info = pair_chain_index.get(lookup)
            if info is not None:
                return info
        return None

    def _apply_chain_scoring(
        self,
        output: Agent1eOutput,
        pairs: List[Dict[str, Any]],
        pair_chain_index: Dict[str, Dict[str, Any]],
    ) -> Agent1eOutput:
        enriched_flow_map = self._enrich_pass1_flow_map(output.pass1_flow_map, pairs)
        if not output.taint_findings:
            return Agent1eOutput(
                file=output.file,
                pass1_flow_map=enriched_flow_map,
                taint_findings=output.taint_findings,
                conflict_resolutions=output.conflict_resolutions,
                clean_paths=output.clean_paths,
                low_confidence_observations=output.low_confidence_observations,
            )

        updated_findings = []
        for finding in output.taint_findings:
            info = self._lookup_chain_info(pair_chain_index, finding)
            if info is None:
                updated_findings.append(finding)
                continue

            chain_length = self._safe_int(info.get("chain_length"), default=0)
            cross_file_hops = self._safe_int(info.get("cross_file_hops"), default=0)
            boundary_hops = list(info.get("boundary_hops", []) or [])
            mapping_ratio = float(info.get("mapping_ratio", 0.0) or 0.0)

            confidence = finding.confidence
            reasoning = list(finding.confidence_reasoning)

            if cross_file_hops > 0:
                decay = min(
                    CHAIN_CONFIDENCE_DECAY_CAP,
                    CHAIN_CONFIDENCE_DECAY_PER_HOP * max(0, cross_file_hops - 1),
                )
                if chain_length > cross_file_hops:
                    decay += 0.02 * (chain_length - cross_file_hops)
                decay = min(CHAIN_CONFIDENCE_DECAY_CAP, decay)
                if decay > 0:
                    confidence = max(0.0, confidence - decay)
                    self._append_reason_once(
                        reasoning,
                        (
                            "Confidence decayed by "
                            f"{decay:.2f} from {cross_file_hops} cross-file hop(s) "
                            f"(chain length {chain_length})."
                        ),
                    )

            if mapping_ratio >= 0.6:
                confidence = min(1.0, confidence + 0.02)
                self._append_reason_once(
                    reasoning,
                    f"Parameter mapping supported across {mapping_ratio:.0%} of chain hops.",
                )
            elif mapping_ratio == 0.0:
                confidence = max(0.0, confidence - 0.03)
                self._append_reason_once(
                    reasoning,
                    "No parameter mapping evidence across chain hops; confidence reduced.",
                )

            sink_fn = str(finding.sink.get("sink_fn", ""))
            if self._has_semgrep_corroboration(output.file, finding.cwe, sink_fn):
                confidence = min(1.0, confidence + 0.03)
                self._append_reason_once(
                    reasoning,
                    "Semgrep corroboration matched file/CWE or sink context.",
                )

            updated_findings.append(
                finding.model_copy(
                    update={
                        "crosses_file_boundary": True,
                        "boundary_hops": boundary_hops,
                        "chain_length": chain_length if chain_length > 0 else None,
                        "confidence": round(confidence, 4),
                        "confidence_reasoning": reasoning,
                    }
                )
            )

        return Agent1eOutput(
            file=output.file,
            pass1_flow_map=enriched_flow_map,
            taint_findings=updated_findings,
            conflict_resolutions=output.conflict_resolutions,
            clean_paths=output.clean_paths,
            low_confidence_observations=output.low_confidence_observations,
        )

    def _enrich_pass1_flow_map(
        self,
        flow_map: List[FlowMapEntry],
        pairs: List[Dict[str, Any]],
    ) -> List[FlowMapEntry]:
        if not flow_map or not pairs:
            return flow_map

        pair_by_source: Dict[str, Dict[str, Any]] = {}
        for pair in pairs:
            if not isinstance(pair, dict):
                continue
            source_var = self._normalize_symbol(pair.get("source_variable", ""))
            if not source_var:
                continue
            linked = pair.get("linked_call_chains", []) or []
            existing = pair_by_source.get(source_var)
            if existing is None or len(linked) > len(existing.get("linked_call_chains", [])):
                pair_by_source[source_var] = pair

        enriched_entries: List[FlowMapEntry] = []
        for entry in flow_map:
            source_var = self._normalize_symbol(entry.source_variable)
            pair = pair_by_source.get(source_var)
            if not pair:
                enriched_entries.append(entry)
                continue

            linked = list(pair.get("linked_call_chains", []) or [])
            current_chain = [step.model_dump() for step in entry.transformation_chain]
            updated_chain, added = self._append_cross_file_steps(current_chain, linked)
            update_payload: Dict[str, Any] = {}
            if linked and (not entry.linked_call_chains):
                update_payload["linked_call_chains"] = linked
            if added > 0:
                update_payload["transformation_chain"] = [
                    TransformationStep(**step) for step in updated_chain
                ]

            if update_payload:
                enriched_entries.append(entry.model_copy(update=update_payload))
            else:
                enriched_entries.append(entry)
        return enriched_entries

    @staticmethod
    def _append_reason_once(reasoning: List[str], reason: str) -> None:
        if reason not in reasoning:
            reasoning.append(reason)

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _normalize_symbol(value: Any) -> str:
        return str(value or "").strip().lower()

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
