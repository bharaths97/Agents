"""Phase 3 advanced validation: longer chains, confidence decay, fallback linker."""

import pytest

from orchestrator.call_graph import CallGraphIndex
from validation.linked_findings import LinkedFindingsResolver


# ---------------------------------------------------------------------------
# Call graph: longer chain (A→B→C→D) detection
# ---------------------------------------------------------------------------


def test_call_graph_detects_longer_chain(fixture_repo_longer_chain):
    """Call graph should resolve at least a 2-hop cross-file chain in the A→B→C→D fixture."""
    code_files = sorted(fixture_repo_longer_chain.rglob("*.py"))
    graph = CallGraphIndex(max_hops=5, max_chains_per_file=20)
    graph.build(fixture_repo_longer_chain, code_files)

    summary = graph.summary()
    assert summary["function_symbols"] >= 4, "Expected 4 symbols (one per file)"
    assert summary["cross_file_edges"] >= 3, "Expected at least 3 cross-file edges (A→B, B→C, C→D)"

    entry_file = str((fixture_repo_longer_chain / "entry.py").resolve())
    hints = graph.file_hints(entry_file)
    assert hints["stats"]["direct_cross_file_call_count"] >= 1
    assert hints["stats"]["cross_file_chain_count"] >= 1

    # At least one chain should reach executor.py
    chains = hints["call_chains"]
    terminal_files = [c["terminal_file"] for c in chains]
    assert any("executor" in tf for tf in terminal_files), (
        "Expected at least one chain reaching executor.py"
    )


def test_call_graph_chain_length_at_least_two(fixture_repo_longer_chain):
    """Chains from entry.py should traverse at least 2 hops."""
    code_files = sorted(fixture_repo_longer_chain.rglob("*.py"))
    graph = CallGraphIndex(max_hops=5, max_chains_per_file=20)
    graph.build(fixture_repo_longer_chain, code_files)

    entry_file = str((fixture_repo_longer_chain / "entry.py").resolve())
    hints = graph.file_hints(entry_file)
    chains = hints["call_chains"]
    assert chains, "Expected at least one chain from entry.py"
    max_len = max(c["chain_length"] for c in chains)
    assert max_len >= 2, f"Expected chain_length >= 2, got {max_len}"


def test_call_graph_parameter_mapping_present(fixture_repo_longer_chain):
    """Hops in the chain should carry parameter mapping where resolvable."""
    code_files = sorted(fixture_repo_longer_chain.rglob("*.py"))
    graph = CallGraphIndex(max_hops=5, max_chains_per_file=20)
    graph.build(fixture_repo_longer_chain, code_files)

    entry_file = str((fixture_repo_longer_chain / "entry.py").resolve())
    hints = graph.file_hints(entry_file)
    chains = hints["call_chains"]
    assert chains

    # At least one hop across all chains should have a non-empty parameter mapping
    all_hops = [hop for chain in chains for hop in chain.get("hops", [])]
    mapped_hops = [hop for hop in all_hops if hop.get("parameter_mapping")]
    assert mapped_hops, "Expected at least one hop with parameter_mapping populated"


def test_call_graph_respects_max_hops(fixture_repo_longer_chain):
    """Setting max_hops=1 should prevent deep chains from being resolved."""
    code_files = sorted(fixture_repo_longer_chain.rglob("*.py"))
    graph = CallGraphIndex(max_hops=1, max_chains_per_file=20)
    graph.build(fixture_repo_longer_chain, code_files)

    entry_file = str((fixture_repo_longer_chain / "entry.py").resolve())
    hints = graph.file_hints(entry_file, max_hops=1)
    chains = hints["call_chains"]
    for chain in chains:
        assert chain["chain_length"] <= 1, (
            f"Chain exceeded max_hops=1: length={chain['chain_length']}"
        )


# ---------------------------------------------------------------------------
# Fallback linker: confidence / decay / dedup behavior
# ---------------------------------------------------------------------------


def test_linked_findings_resolver_link_confidence_decay():
    """_link_confidence should decay with chain length and be lower without terminal findings."""
    resolver = LinkedFindingsResolver()

    # linked_to_terminal=True: base 0.45, decay 0.04 per hop beyond 1
    assert resolver._link_confidence(1, linked_to_terminal=True) == 0.45   # no decay at length 1
    assert resolver._link_confidence(2, linked_to_terminal=True) == 0.41   # 0.45 - 0.04
    assert resolver._link_confidence(3, linked_to_terminal=True) == 0.37   # 0.45 - 0.08
    assert resolver._link_confidence(4, linked_to_terminal=True) == 0.33   # 0.45 - 0.12

    # linked_to_terminal=False: base 0.30, decay 0.04 per hop beyond 1
    assert resolver._link_confidence(1, linked_to_terminal=False) == 0.30
    assert resolver._link_confidence(2, linked_to_terminal=False) == 0.26
    assert resolver._link_confidence(3, linked_to_terminal=False) == 0.22
    assert resolver._link_confidence(4, linked_to_terminal=False) == 0.18

    # Floor at 0.15
    assert resolver._link_confidence(100, linked_to_terminal=True) == 0.15
    assert resolver._link_confidence(100, linked_to_terminal=False) == 0.15


def test_linked_findings_resolver_confidence_always_positive():
    """_link_confidence should never go below 0.15 regardless of chain length."""
    resolver = LinkedFindingsResolver()
    for length in range(1, 30):
        for terminal in (True, False):
            result = resolver._link_confidence(length, linked_to_terminal=terminal)
            assert result >= 0.15, (
                f"Confidence went below floor: length={length}, terminal={terminal}, got {result}"
            )


def test_linked_findings_resolver_no_outputs_returns_empty():
    """link_outputs with empty list should return empty results."""
    resolver = LinkedFindingsResolver()
    outputs, records = resolver.link_outputs([], call_graph_index=None)
    assert outputs == []
    assert records == []


def test_linked_findings_resolver_no_graph_returns_unchanged():
    """link_outputs without a call graph index should return outputs unchanged."""
    from unittest.mock import MagicMock
    from schemas.models import Agent1eOutput

    resolver = LinkedFindingsResolver()
    mock_output = MagicMock(spec=Agent1eOutput)
    outputs, records = resolver.link_outputs([mock_output], call_graph_index=None)
    assert outputs == [mock_output]
    assert records == []


# ---------------------------------------------------------------------------
# Agent 1e chain confidence decay constants
# ---------------------------------------------------------------------------


def test_agent1e_chain_decay_constants():
    """Lock the decay constants that drive cross-file confidence scoring."""
    from agents.agent_1e import CHAIN_CONFIDENCE_DECAY_PER_HOP, CHAIN_CONFIDENCE_DECAY_CAP

    # These values are tested to lock scoring stability.
    # If changed intentionally, update these assertions to match.
    assert CHAIN_CONFIDENCE_DECAY_PER_HOP == 0.04, (
        f"Decay per hop changed: expected 0.04, got {CHAIN_CONFIDENCE_DECAY_PER_HOP}"
    )
    assert CHAIN_CONFIDENCE_DECAY_CAP == 0.35, (
        f"Decay cap changed: expected 0.35, got {CHAIN_CONFIDENCE_DECAY_CAP}"
    )


def test_agent1e_chain_decay_math():
    """Validate chain decay arithmetic matches expected values for 1–4 cross-file hops."""
    from agents.agent_1e import CHAIN_CONFIDENCE_DECAY_PER_HOP, CHAIN_CONFIDENCE_DECAY_CAP

    base_confidence = 0.80

    for cross_file_hops in range(1, 5):
        decay = min(
            CHAIN_CONFIDENCE_DECAY_CAP,
            CHAIN_CONFIDENCE_DECAY_PER_HOP * max(0, cross_file_hops - 1),
        )
        result = round(max(0.0, base_confidence - decay), 4)
        assert result > 0.0, f"Confidence hit zero at {cross_file_hops} hops"
        assert result <= base_confidence, "Confidence should not exceed base"

    # 1 hop: no decay (factor is max(0, 1-1) = 0)
    decay_1 = min(CHAIN_CONFIDENCE_DECAY_CAP, CHAIN_CONFIDENCE_DECAY_PER_HOP * 0)
    assert decay_1 == 0.0

    # 4 hops: 0.04 * 3 = 0.12
    decay_4 = min(CHAIN_CONFIDENCE_DECAY_CAP, CHAIN_CONFIDENCE_DECAY_PER_HOP * 3)
    assert decay_4 == pytest.approx(0.12)

    # 10 hops: capped at 0.35
    decay_10 = min(CHAIN_CONFIDENCE_DECAY_CAP, CHAIN_CONFIDENCE_DECAY_PER_HOP * 9)
    assert decay_10 == pytest.approx(0.35)


# ---------------------------------------------------------------------------
# Chain signature deduplication
# ---------------------------------------------------------------------------


def test_chain_signature_is_deterministic():
    """_chain_signature should return the same string for identical chain dicts."""
    resolver = LinkedFindingsResolver()

    chain = {
        "hops": [
            {"from_file": "a.py", "from_function": "foo", "to_file": "b.py", "to_function": "bar", "call_line": 5},
            {"from_file": "b.py", "from_function": "bar", "to_file": "c.py", "to_function": "baz", "call_line": 10},
        ]
    }
    sig1 = resolver._chain_signature(chain)
    sig2 = resolver._chain_signature(chain)
    assert sig1 == sig2
    assert len(sig1) > 0


def test_chain_signature_differs_for_different_chains():
    """Different chains should produce different signatures."""
    resolver = LinkedFindingsResolver()

    chain_a = {
        "hops": [
            {"from_file": "a.py", "from_function": "foo", "to_file": "b.py", "to_function": "bar", "call_line": 5},
        ]
    }
    chain_b = {
        "hops": [
            {"from_file": "x.py", "from_function": "foo", "to_file": "y.py", "to_function": "baz", "call_line": 99},
        ]
    }
    assert resolver._chain_signature(chain_a) != resolver._chain_signature(chain_b)
