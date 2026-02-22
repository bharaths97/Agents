"""Phase 3 integration sanity checks."""

from unittest.mock import AsyncMock, patch

import pytest

from config import settings
from orchestrator.call_graph import CallGraphIndex
from orchestrator.control_plane import TaintAnalystOrchestrator
from schemas.models import Agent1aOutput, Agent1bOutput, Agent1cOutput, ThreatModel
from tooling.semgrep_runner import SemgrepScanResult


def test_phase3_call_graph_multifile_fixture(fixture_repo_multifile):
    """Phase 3 call graph should resolve cross-file chain for multifile Python fixture."""
    code_files = sorted(fixture_repo_multifile.rglob("*.py"))
    graph = CallGraphIndex(max_hops=5, max_chains_per_file=20)
    graph.build(fixture_repo_multifile, code_files)

    summary = graph.summary()
    assert summary["function_symbols"] >= 2
    assert summary["cross_file_edges"] >= 1

    hints = graph.file_hints(str((fixture_repo_multifile / "api.py").resolve()))
    assert hints["stats"]["direct_cross_file_call_count"] >= 1
    assert hints["stats"]["cross_file_chain_count"] >= 1


@pytest.mark.asyncio
async def test_phase3_flag_enables_orchestrator_call_graph(fixture_repo_multifile):
    """Orchestrator should build and publish call graph metadata when Phase 3 flag is on."""
    orchestrator = TaintAnalystOrchestrator(
        repo_path=fixture_repo_multifile,
        model="gpt-4o",
    )

    out_1a = Agent1aOutput(
        domain="web application",
        domain_risk_tier="MEDIUM",
        domain_risk_reasoning="Fixture repository for integration testing",
        regulatory_context=[],
        user_types=[{"type": "anonymous", "trust_level": "UNTRUSTED", "description": "external user"}],
        data_handled=[{"data_type": "search query", "sensitivity": "PUBLIC", "notes": "demo fixture"}],
        component_intent_map={},
        intended_security_posture="baseline controls",
        deployment_context={
            "environment": "cloud",
            "publicly_exposed": True,
            "authentication_mechanism": "none",
            "notable_infrastructure": [],
        },
        test_derived_assumptions=[],
        notable_developer_comments=[],
        flags=[],
    )
    out_1b = Agent1bOutput(
        semantics_map={
            "api.py::search": {
                "intended": "Search handler",
                "actual": "Passes input to db helper",
                "diverges": False,
                "divergence_note": "",
            }
        },
        insecure_practice_findings=[],
    )
    out_1c = Agent1cOutput(data_taxonomy={}, logging_findings=[])
    threat_model = ThreatModel(
        methodology="STRIDE",
        domain="web application",
        domain_risk_tier="MEDIUM",
        regulatory_context=[],
        assets=[],
        trust_boundaries=[],
        attack_surface=[],
        stride_analysis=[],
        prioritized_threat_scenarios=[],
    )
    semgrep = SemgrepScanResult(
        enabled=False,
        rules_root=str(fixture_repo_multifile),
        rules_indexed=0,
        rules_selected=0,
        findings=[],
        selection_rationale={},
    )

    with patch.object(settings, "phase3_cross_file_enabled", True), patch.object(
        settings, "phase3_call_graph_max_hops", 5
    ), patch.object(settings, "phase3_call_graph_max_chains_per_file", 20), patch(
        "agents.semgrep_evidence_agent.SemgrepEvidenceAgent.run",
        new=AsyncMock(return_value=semgrep),
    ), patch(
        "agents.agent_1a.Agent1a.run",
        new=AsyncMock(return_value=out_1a),
    ), patch(
        "agents.agent_1b.Agent1b.run",
        new=AsyncMock(return_value=out_1b),
    ), patch(
        "agents.agent_1c.Agent1c.run",
        new=AsyncMock(return_value=out_1c),
    ), patch(
        "agents.agent_1d.Agent1d.run",
        new=AsyncMock(return_value=threat_model),
    ), patch(
        "agents.agent_1e.Agent1e.run",
        new=AsyncMock(return_value=[]),
    ):
        result = await orchestrator.run()

    assert result.summary["phase3_cross_file_enabled"] is True
    assert result.summary["call_graph_available"] is True
    assert result.call_graph["available"] is True
    assert result.call_graph["stats"]["cross_file_edges"] >= 1
