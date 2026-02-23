"""
Agent 1d — Terrain Synthesizer + Threat Modeler

Stage: Synthesis (sequential after Ring 0, streaming)

Does NOT read source code. Receives structured JSON from 1a, 1b, and 1c:
  1. Synthesizes per-file terrain objects → streamed to asyncio.Queue for Agent 1e
  2. Produces one system-wide STRIDE threat model → returned after all terrain is emitted
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Set

from .base import BaseAgent
from .code_scanner_prompts import AGENT_BASE_INSTRUCTIONS, AGENT_1D_SYNTHESIZER
from schemas.models import (
    Agent1aOutput,
    Agent1bOutput,
    Agent1cOutput,
    CtfArtifacts,
    CtfFlagHit,
    TerrainObject,
    ThreatModel,
    ThreatModelOutput,
)

logger = logging.getLogger(__name__)

# Sentinel: tells Agent 1e that the stream is complete
TERRAIN_DONE = object()

TERRAIN_SYSTEM_PROMPT = (
    AGENT_BASE_INSTRUCTIONS
    + "\n\n"
    + AGENT_1D_SYNTHESIZER
    + """

════════════════════════════════════════════════════════════════
CALL MODE: PER-FILE TERRAIN SYNTHESIS
════════════════════════════════════════════════════════════════

You are being called to synthesize the terrain object for a SINGLE FILE.
Output a single JSON object (not an array) matching the per-file terrain schema.
The file path is given in the user message.
"""
)

THREAT_MODEL_SYSTEM_PROMPT = (
    AGENT_BASE_INSTRUCTIONS
    + "\n\n"
    + AGENT_1D_SYNTHESIZER
    + """

════════════════════════════════════════════════════════════════
CALL MODE: SYSTEM-WIDE THREAT MODEL
════════════════════════════════════════════════════════════════

All per-file terrain has been synthesized. You are now producing the single
system-wide threat model. Output ONLY the JSON object with the "ctf_artifacts" and
"threat_model" keys.
"""
)


class Agent1d(BaseAgent):
    name = "Agent1d-TerrainSynthesizerThreatModeler"

    async def run(
        self,
        output_1a: Agent1aOutput,
        output_1b: Agent1bOutput,
        output_1c: Agent1cOutput,
        terrain_queue: asyncio.Queue,
    ) -> ThreatModelOutput:
        """
        Synthesize terrain from Ring 0 outputs. Streams per-file TerrainObjects to
        terrain_queue for Agent 1e. Returns the system-wide threat model.

        Args:
            output_1a: Domain model from Agent 1a
            output_1b: Semantics + insecure practices from Agent 1b
            output_1c: Data taxonomy + logging findings from Agent 1c
            terrain_queue: asyncio.Queue — TerrainObjects go here for Agent 1e

        Returns:
            ThreatModelOutput (system-wide, one per analysis run)
        """
        logger.info(f"[{self.name}] Starting terrain synthesis")

        all_files = self._collect_files(output_1b, output_1c)
        all_ctf_hits = self._collect_ctf_hits(output_1a, output_1b, output_1c)
        all_terrains: List[TerrainObject] = []

        rag_context = await self.retrieve_references(
            "taint analysis source sink trust boundary attack surface STRIDE threat model"
        )

        # Stream per-file terrain objects to Agent 1e as they are produced
        for file_path in all_files:
            terrain = await self._synthesize_file_terrain(
                file_path=file_path,
                output_1a=output_1a,
                output_1b=output_1b,
                output_1c=output_1c,
                rag_context=rag_context,
                ctf_hits=all_ctf_hits,
            )
            all_terrains.append(terrain)
            await terrain_queue.put(terrain)
            logger.debug(f"[{self.name}] Emitted terrain for {file_path}")

        # Produce the threat model once all per-file terrain is done
        threat_bundle = await self._produce_threat_model(
            output_1a,
            all_terrains,
            rag_context,
            all_ctf_hits,
        )

        # Signal to Agent 1e that the stream is complete
        await terrain_queue.put(TERRAIN_DONE)

        logger.info(
            f"[{self.name}] Complete — {len(all_terrains)} terrain objects, "
            f"{len(threat_bundle.threat_model.stride_analysis)} STRIDE threats, "
            f"{len(threat_bundle.threat_model.prioritized_threat_scenarios)} scenarios"
        )
        return threat_bundle

    def _collect_files(
        self, output_1b: Agent1bOutput, output_1c: Agent1cOutput
    ) -> List[str]:
        """Collect unique file paths referenced in 1b and 1c outputs."""
        files: Set[str] = set()
        for key in output_1b.semantics_map:
            files.add(key.split("::")[0])
        for finding in output_1b.insecure_practice_findings:
            files.add(finding.file)
        for key in output_1c.data_taxonomy:
            files.add(key.split("::")[0])
        for finding in output_1c.logging_findings:
            files.add(finding.file)
        return sorted(files)

    async def _synthesize_file_terrain(
        self,
        file_path: str,
        output_1a: Agent1aOutput,
        output_1b: Agent1bOutput,
        output_1c: Agent1cOutput,
        rag_context: str,
        ctf_hits: List[CtfFlagHit],
    ) -> TerrainObject:
        """Synthesize terrain for a single file."""

        file_semantics = {
            k: v for k, v in output_1b.semantics_map.items()
            if k.startswith(file_path)
        }
        file_insecure = [
            f for f in output_1b.insecure_practice_findings
            if f.file == file_path
        ]
        file_taxonomy = {
            k: v for k, v in output_1c.data_taxonomy.items()
            if k.startswith(file_path)
        }
        file_logging = [
            f for f in output_1c.logging_findings
            if f.file == file_path
        ]

        user_prompt = f"""Synthesize the per-file terrain object for: {file_path}

## Agent 1a — Domain Model
Domain: {output_1a.domain}
Risk Tier: {output_1a.domain_risk_tier}
Risk Reasoning: {output_1a.domain_risk_reasoning}
Regulatory: {output_1a.regulatory_context}
Security Posture: {output_1a.intended_security_posture}
Component Intent: {output_1a.component_intent_map.get(file_path, 'Not documented')}
Flags: {output_1a.flags}

## Agent 1b — Semantics Map for this file
{json.dumps({k: v.model_dump() for k, v in file_semantics.items()}, indent=2)}

## Agent 1b — Insecure Practice Findings for this file
{json.dumps([f.model_dump() for f in file_insecure], indent=2)}

## Agent 1c — Data Taxonomy for this file
{json.dumps({k: v.model_dump() for k, v in file_taxonomy.items()}, indent=2)}

## Agent 1c — Logging Findings for this file
{json.dumps([f.model_dump() for f in file_logging], indent=2)}

{rag_context}

Synthesize the unified terrain object for this file. Identify sources and sinks from
the semantics and taxonomy data. Apply domain risk amplification. Flag all conflicts.
Output ONLY the single per-file terrain JSON object (not an array).
"""

        file_ctf_hits = [hit for hit in ctf_hits if hit.file == file_path]

        try:
            raw = await self.call_llm(
                system_prompt=TERRAIN_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.1,
            )
            # If model returns an array (should not happen), take first element
            if isinstance(raw, list):
                raw = raw[0]
            terrain = TerrainObject(**raw)
            if file_ctf_hits:
                terrain = terrain.model_copy(update={"ctf_flag_hits": file_ctf_hits})
            return terrain
        except Exception as exc:
            logger.error(f"[{self.name}] Terrain synthesis failed for {file_path}: {exc}")
            return TerrainObject(
                file=file_path,
                domain_context=f"Synthesis failed: {exc}",
                domain_risk_tier="LOW",
                sources=[],
                sinks=[],
                insecure_practice_findings=[],
                logging_findings=[],
                conflicts=[],
                intent_divergences=[],
                priority_findings=[],
                ctf_flag_hits=file_ctf_hits,
            )

    async def _produce_threat_model(
        self,
        output_1a: Agent1aOutput,
        all_terrains: List[TerrainObject],
        rag_context: str,
        ctf_hits: List[CtfFlagHit],
    ) -> ThreatModelOutput:
        """Produce the system-wide STRIDE threat model once all terrain is ready."""

        all_sources = [
            s.model_dump() | {"_file": t.file}
            for t in all_terrains
            for s in t.sources
        ]
        all_sinks = [
            s.model_dump() | {"_file": t.file}
            for t in all_terrains
            for s in t.sinks
        ]
        all_practices = [
            pf for t in all_terrains for pf in t.insecure_practice_findings
        ]

        user_prompt = f"""Produce the system-wide STRIDE threat model.

## Agent 1a — Full Domain Model
{json.dumps(output_1a.model_dump(), indent=2)}

## All Identified Sources (all files)
{json.dumps(all_sources, indent=2)}

## All Identified Sinks (all files)
{json.dumps(all_sinks, indent=2)}

## Insecure Practice Findings (top 30)
{json.dumps([p.model_dump() if hasattr(p, 'model_dump') else p for p in all_practices[:30]], indent=2)}

## File Risk Summary
{json.dumps([(t.file, t.domain_risk_tier) for t in all_terrains], indent=2)}

{rag_context}

Produce the complete STRIDE threat model. Every threat must cite upstream evidence.
Include specific taint path hints in prioritized_threat_scenarios for Agent 1e.
Output ONLY the JSON object with the "threat_model" key.
"""

        try:
            raw = await self.call_llm(
                system_prompt=THREAT_MODEL_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                temperature=0.15,
            )
            threat_payload = raw.get("threat_model", raw)
            threat_model = ThreatModel(**threat_payload)
            return ThreatModelOutput(
                ctf_artifacts=self._build_ctf_artifacts(ctf_hits),
                threat_model=threat_model,
            )
        except Exception as exc:
            logger.error(f"[{self.name}] Threat model production failed: {exc}")
            return ThreatModelOutput(
                ctf_artifacts=self._build_ctf_artifacts(ctf_hits),
                threat_model=ThreatModel(
                    methodology="STRIDE",
                    domain=output_1a.domain,
                    domain_risk_tier=output_1a.domain_risk_tier,
                    regulatory_context=output_1a.regulatory_context,
                    assets=[],
                    trust_boundaries=[],
                    attack_surface=[],
                    stride_analysis=[],
                    prioritized_threat_scenarios=[],
                ),
            )

    @staticmethod
    def _collect_ctf_hits(
        output_1a: Agent1aOutput,
        output_1b: Agent1bOutput,
        output_1c: Agent1cOutput,
    ) -> List[CtfFlagHit]:
        hits: List[CtfFlagHit] = []
        hits.extend(output_1a.ctf_flag_hits or [])
        hits.extend(output_1b.ctf_flag_hits or [])
        hits.extend(output_1c.ctf_flag_hits or [])
        if not hits:
            return []
        seen = set()
        unique: List[CtfFlagHit] = []
        for hit in hits:
            key = (hit.match, hit.file, hit.line_start, hit.line_end)
            if key in seen:
                continue
            seen.add(key)
            unique.append(hit)
        return unique

    @staticmethod
    def _build_ctf_artifacts(hits: List[CtfFlagHit]) -> CtfArtifacts:
        if not hits:
            return CtfArtifacts(summary="", hits=[])
        summary = f"{len(hits)} potential CTF flag artifact(s) detected."
        return CtfArtifacts(summary=summary, hits=hits)
