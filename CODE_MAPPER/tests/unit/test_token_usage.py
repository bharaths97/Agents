from types import SimpleNamespace

from agents.base import BaseAgent


def test_record_token_usage_from_response_usage_object():
    agent = BaseAgent(model="gpt-4o")

    usage = SimpleNamespace(
        prompt_tokens=120,
        completion_tokens=45,
        total_tokens=165,
        prompt_tokens_details=SimpleNamespace(cached_tokens=20),
        completion_tokens_details=SimpleNamespace(reasoning_tokens=11),
    )
    response = SimpleNamespace(usage=usage)

    agent._record_token_usage(response)
    stats = agent.get_token_usage()

    assert stats["calls"] == 1
    assert stats["prompt_tokens"] == 120
    assert stats["completion_tokens"] == 45
    assert stats["total_tokens"] == 165
    assert stats["cached_tokens"] == 20
    assert stats["reasoning_tokens"] == 11


def test_record_token_usage_without_usage_object_counts_call_only():
    agent = BaseAgent(model="gpt-4o")
    response = SimpleNamespace(usage=None)

    agent._record_token_usage(response)
    stats = agent.get_token_usage()

    assert stats["calls"] == 1
    assert stats["prompt_tokens"] == 0
    assert stats["completion_tokens"] == 0
    assert stats["total_tokens"] == 0
