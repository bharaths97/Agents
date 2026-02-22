from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from agents.agent_1a import Agent1a
from agents.agent_1b import Agent1b
from agents.agent_1c import Agent1c
from agents.agent_1d import Agent1d
from agents.agent_1e import Agent1e
from agents.semgrep_evidence_agent import SemgrepEvidenceAgent
from config import settings
from rag import RAGStore
from schemas.models import Agent1eOutput, CtfArtifacts, ThreatModel, ThreatModelOutput
from tooling import SemgrepScanResult
from validation import LinkedFindingsResolver, SchemaValidator

from .call_graph import CallGraphIndex
from .repo_scanner import RepoScanResult, RepoScanner

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    scan: RepoScanResult
    call_graph: Dict[str, Any]
    phase3_links: List[Dict[str, Any]]
    ctf_artifacts: Dict[str, Any]
    agent_1a: Dict[str, Any]
    agent_1b: Dict[str, Any]
    agent_1c: Dict[str, Any]
    semgrep: Dict[str, Any]
    threat_model: Dict[str, Any]
    taint_outputs: List[Dict[str, Any]]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan": {
                "code_files": [str(p) for p in self.scan.code_files],
                "context_files": [str(p) for p in self.scan.context_files],
                "unknown_files": [str(p) for p in self.scan.unknown_files],
                "detected_languages": self.scan.detected_languages,
                "detected_frameworks": self.scan.detected_frameworks,
                "detected_infra": self.scan.detected_infra,
                "manifests": [str(p) for p in self.scan.manifests],
            },
            "call_graph": self.call_graph,
            "phase3_links": self.phase3_links,
            "ctf_artifacts": self.ctf_artifacts,
            "agent_1a": self.agent_1a,
            "agent_1b": self.agent_1b,
            "agent_1c": self.agent_1c,
            "semgrep": self.semgrep,
            "threat_model": self.threat_model,
            "agent_1e": self.taint_outputs,
            "summary": self.summary,
        }


class TaintAnalystOrchestrator:
    """Control plane for Ring 0 + Stage 2 orchestration."""

    def __init__(self, repo_path: Path, model: str | None = None):
        self.repo_path = repo_path
        self.model = model or settings.openai_model
        self.validator = SchemaValidator()

    async def run(self) -> AnalysisResult:
        scan = RepoScanner(self.repo_path).scan()
        logger.info(
            "[Orchestrator] Scan complete: %d code files, %d context files",
            len(scan.code_files),
            len(scan.context_files),
        )

        call_graph_summary: Dict[str, Any] = {
            "enabled": settings.phase3_cross_file_enabled,
            "available": False,
            "stats": {},
        }
        call_graph_index = None
        if settings.phase3_cross_file_enabled:
            call_graph_index = CallGraphIndex(
                max_hops=settings.phase3_call_graph_max_hops,
                max_chains_per_file=settings.phase3_call_graph_max_chains_per_file,
            )
            try:
                await asyncio.to_thread(call_graph_index.build, self.repo_path, scan.code_files)
                call_graph_summary = {
                    "enabled": True,
                    "available": True,
                    "stats": call_graph_index.summary(),
                    "max_hops": settings.phase3_call_graph_max_hops,
                    "max_chains_per_file": settings.phase3_call_graph_max_chains_per_file,
                }
            except Exception as exc:
                logger.warning("[Orchestrator] Call graph build failed: %s", exc)
                call_graph_index = None
                call_graph_summary = {
                    "enabled": True,
                    "available": False,
                    "error": str(exc),
                    "stats": {},
                }

        rag_store = RAGStore(self._resolve_rag_docs())
        await rag_store.initialize()

        semgrep_agent = SemgrepEvidenceAgent(
            rules_root=self._resolve_semgrep_rules_root(),
            repo_path=self.repo_path,
        )
        semgrep_result: SemgrepScanResult = await semgrep_agent.run(scan)
        semgrep_findings_by_file = semgrep_result.findings_by_file()
        if semgrep_result.error:
            logger.warning("[Orchestrator] Semgrep issue: %s", semgrep_result.error)
        else:
            logger.info(
                "[Orchestrator] Semgrep complete: %d findings from %d selected rules",
                len(semgrep_result.findings),
                semgrep_result.rules_selected,
            )

        # Stage 1 (Ring 0): run in parallel.
        agent_1a = Agent1a(model=self.model, rag_store=rag_store)
        agent_1b = Agent1b(model=self.model, rag_store=rag_store)
        agent_1c = Agent1c(model=self.model, rag_store=rag_store)

        task_1a = asyncio.create_task(agent_1a.run(scan.context_files))
        task_1b = asyncio.create_task(
            agent_1b.run(
                scan.code_files,
                semgrep_findings_by_file=semgrep_findings_by_file,
            )
        )
        task_1c = asyncio.create_task(agent_1c.run(scan.code_files, domain_output=None))

        out_1a, out_1b, out_1c = await asyncio.gather(task_1a, task_1b, task_1c)
        out_1a = self.validator.validate_1a_output(out_1a)
        out_1b = self.validator.validate_1b_output(out_1b)
        out_1c = self.validator.validate_1c_output(out_1c)

        # Stage 2: 1d streams terrain to queue while 1e consumes.
        terrain_queue: asyncio.Queue = asyncio.Queue()
        agent_1d = Agent1d(model=self.model, rag_store=rag_store)
        agent_1e = Agent1e(
            model=self.model,
            rag_store=rag_store,
            repo_path=self.repo_path,
            semgrep_findings_by_file=semgrep_findings_by_file,
            call_graph_index=call_graph_index,
        )

        task_1e = asyncio.create_task(agent_1e.run(terrain_queue))
        threat_bundle = await agent_1d.run(out_1a, out_1b, out_1c, terrain_queue)
        if threat_bundle is None:
            threat_bundle = ThreatModelOutput(
                ctf_artifacts=CtfArtifacts(summary="", hits=[]),
                threat_model=ThreatModel(
                    methodology="STRIDE",
                    domain=out_1a.domain,
                    domain_risk_tier=out_1a.domain_risk_tier,
                    regulatory_context=out_1a.regulatory_context,
                    assets=[],
                    trust_boundaries=[],
                    attack_surface=[],
                    stride_analysis=[],
                    prioritized_threat_scenarios=[],
                ),
            )
        threat_model = threat_bundle.threat_model
        agent_1e.threat_model = threat_model
        out_1e: List[Agent1eOutput] = await task_1e

        phase3_links: List[Dict[str, Any]] = []
        if settings.phase3_cross_file_enabled and call_graph_index is not None:
            linker = LinkedFindingsResolver()
            out_1e, phase3_links = linker.link_outputs(out_1e, call_graph_index=call_graph_index)

        summary = {
            "files_analyzed": len(scan.code_files),
            "context_files_analyzed": len(scan.context_files),
            "unknown_files": len(scan.unknown_files),
            "insecure_practice_findings": len(out_1b.insecure_practice_findings),
            "logging_findings": len(out_1c.logging_findings),
            "taint_findings": sum(len(item.taint_findings) for item in out_1e),
            "threat_scenarios": len(threat_model.prioritized_threat_scenarios),
            "ring1_candidates": self._determine_ring1_candidates(scan),
            "semgrep_rules_selected": semgrep_result.rules_selected,
            "semgrep_findings": len(semgrep_result.findings),
            "semgrep_error": semgrep_result.error,
            "phase3_cross_file_enabled": settings.phase3_cross_file_enabled,
            "call_graph_available": bool(call_graph_index),
            "call_graph_cross_file_edges": (
                call_graph_summary.get("stats", {}).get("cross_file_edges", 0)
                if call_graph_summary
                else 0
            ),
            "phase3_linked_observations": len(phase3_links),
        }

        return AnalysisResult(
            scan=scan,
            call_graph=call_graph_summary,
            phase3_links=phase3_links,
            ctf_artifacts=threat_bundle.ctf_artifacts.model_dump(),
            agent_1a=out_1a.model_dump(),
            agent_1b=out_1b.model_dump(),
            agent_1c=out_1c.model_dump(),
            semgrep=semgrep_result.to_dict(),
            threat_model=threat_model.model_dump(),
            taint_outputs=[item.model_dump() for item in out_1e],
            summary=summary,
        )

    def _resolve_rag_docs(self) -> Path:
        docs_path = Path(settings.rag_docs_path)
        if not docs_path.is_absolute():
            docs_path = Path(__file__).resolve().parent.parent / docs_path
        return docs_path

    def _resolve_semgrep_rules_root(self) -> Path:
        rules_root = Path(settings.semgrep_rules_root)
        if not rules_root.is_absolute():
            rules_root = Path(__file__).resolve().parent.parent / rules_root
        return rules_root

    @staticmethod
    def _determine_ring1_candidates(scan: RepoScanResult) -> List[str]:
        candidates: List[str] = []
        for suffix in scan.detected_languages:
            if suffix == ".py":
                candidates.append("ring1-language-python")
            elif suffix in {".js", ".ts", ".jsx", ".tsx"}:
                candidates.append("ring1-language-javascript")
            elif suffix == ".go":
                candidates.append("ring1-language-go")
            elif suffix == ".java":
                candidates.append("ring1-language-java")

        for framework in scan.detected_frameworks:
            candidates.append(f"ring1-framework-{framework}")
        for infra in scan.detected_infra:
            candidates.append(f"ring1-infra-{infra}")
        return sorted(set(candidates))
