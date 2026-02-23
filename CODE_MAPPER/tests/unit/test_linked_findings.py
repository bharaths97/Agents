"""Unit tests for Phase 3 linked-findings fallback resolver."""

from pathlib import Path

from schemas.models import Agent1eOutput
from validation.linked_findings import LinkedFindingsResolver


class _StubCallGraph:
    def __init__(self, hints_by_file):
        self._hints_by_file = {
            str(Path(file_path).resolve()): payload for file_path, payload in hints_by_file.items()
        }

    def file_hints(self, file_path):
        key = str(Path(file_path).resolve())
        return self._hints_by_file.get(
            key,
            {"file": key, "direct_cross_file_calls": [], "call_chains": [], "stats": {}},
        )


def _minimal_finding(finding_id: str):
    return {
        "id": finding_id,
        "source": {"variable": "input", "line": 3, "type": "http_param"},
        "sink": {"variable": "sql", "line": 8, "sink_fn": "execute", "type": "sql_exec"},
        "taint_path": ["input -> sql"],
        "sanitization": {"exists": False, "correct": False, "sufficient": False, "details": "none"},
        "vulnerability": "SQL_INJECTION",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "domain_risk_context": "MEDIUM",
        "exploit_scenario": "unsanitized parameter in SQL string",
        "verification_1_reachability": "reachable",
        "verification_2_sanitization": "insufficient",
        "verification_3_adversarial": "not refuted",
        "confidence": 0.7,
        "confidence_reasoning": ["Source and sink are directly connected."],
        "false_positive_risk": "LOW",
        "false_positive_notes": "Fixture finding",
        "remediation": "Use parameterized query",
    }


def test_linked_findings_adds_unresolved_multihop_observation(tmp_path):
    resolver = LinkedFindingsResolver()
    source_file = tmp_path / "api.py"
    mid_file = tmp_path / "service.py"
    terminal_file = tmp_path / "db.py"
    for file_path in (source_file, mid_file, terminal_file):
        file_path.write_text("# fixture\n")

    source_output = Agent1eOutput(file=str(source_file), taint_findings=[])
    terminal_output = Agent1eOutput(file=str(terminal_file), taint_findings=[])

    hints = {
        str(source_file): {
            "file": str(source_file),
            "direct_cross_file_calls": [],
            "call_chains": [
                # single-hop unresolved path should be ignored by fallback
                {
                    "start_file": str(source_file),
                    "start_function": "search",
                    "terminal_file": str(terminal_file),
                    "terminal_function": "execute_query",
                    "chain_length": 1,
                    "hops": [
                        {
                            "from_file": str(source_file),
                            "from_function": "search",
                            "to_file": str(terminal_file),
                            "to_function": "execute_query",
                            "call_line": 8,
                            "parameter_mapping": {"query": "search_term"},
                        }
                    ],
                },
                # unresolved multi-hop path should be materialized
                {
                    "start_file": str(source_file),
                    "start_function": "search",
                    "terminal_file": str(terminal_file),
                    "terminal_function": "execute_query",
                    "chain_length": 3,
                    "hops": [
                        {
                            "from_file": str(source_file),
                            "from_function": "search",
                            "to_file": str(mid_file),
                            "to_function": "prepare_query",
                            "call_line": 8,
                            "parameter_mapping": {"input": "search_term"},
                        },
                        {
                            "from_file": str(mid_file),
                            "from_function": "prepare_query",
                            "to_file": str(mid_file),
                            "to_function": "build_sql",
                            "call_line": 12,
                            "parameter_mapping": {"input": "term"},
                        },
                        {
                            "from_file": str(mid_file),
                            "from_function": "build_sql",
                            "to_file": str(terminal_file),
                            "to_function": "execute_query",
                            "call_line": 18,
                            "parameter_mapping": {"sql": "statement"},
                        },
                    ],
                },
            ],
            "stats": {"cross_file_chain_count": 2},
        }
    }
    graph = _StubCallGraph(hints)

    updated_outputs, linked = resolver.link_outputs(
        outputs=[source_output, terminal_output],
        call_graph_index=graph,
    )

    assert len(linked) == 1
    assert linked[0]["status"] == "unresolved_chain"
    assert linked[0]["chain_length"] == 3
    assert linked[0]["confidence"] == 0.22

    source_observations = updated_outputs[0].low_confidence_observations
    assert len(source_observations) == 1
    assert source_observations[0].confidence == 0.22
    assert "3 hop chain" in source_observations[0].note


def test_linked_findings_links_to_terminal_findings_with_confidence_decay(tmp_path):
    resolver = LinkedFindingsResolver()
    source_file = tmp_path / "api.py"
    terminal_file = tmp_path / "db.py"
    for file_path in (source_file, terminal_file):
        file_path.write_text("# fixture\n")

    source_output = Agent1eOutput(file=str(source_file), taint_findings=[])
    terminal_output = Agent1eOutput(
        file=str(terminal_file),
        taint_findings=[_minimal_finding("TF-001")],
    )

    hints = {
        str(source_file): {
            "file": str(source_file),
            "direct_cross_file_calls": [],
            "call_chains": [
                {
                    "start_file": str(source_file),
                    "start_function": "search",
                    "terminal_file": str(terminal_file),
                    "terminal_function": "execute_query",
                    "chain_length": 2,
                    "hops": [
                        {
                            "from_file": str(source_file),
                            "from_function": "search",
                            "to_file": str(terminal_file),
                            "to_function": "build_sql",
                            "call_line": 9,
                            "parameter_mapping": {"input": "search_term"},
                        },
                        {
                            "from_file": str(terminal_file),
                            "from_function": "build_sql",
                            "to_file": str(terminal_file),
                            "to_function": "execute_query",
                            "call_line": 16,
                            "parameter_mapping": {"sql": "statement"},
                        },
                    ],
                }
            ],
            "stats": {"cross_file_chain_count": 1},
        }
    }
    graph = _StubCallGraph(hints)

    updated_outputs, linked = resolver.link_outputs(
        outputs=[source_output, terminal_output],
        call_graph_index=graph,
    )

    assert len(linked) == 1
    assert linked[0]["status"] == "linked_to_terminal_finding"
    assert linked[0]["terminal_finding_ids"] == ["TF-001"]
    assert linked[0]["confidence"] == 0.41

    source_observations = updated_outputs[0].low_confidence_observations
    assert len(source_observations) == 1
    assert source_observations[0].confidence == 0.41
