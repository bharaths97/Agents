from types import SimpleNamespace

import pytest

from agents.agent_1e import Agent1e


@pytest.mark.asyncio
async def test_focused_source_falls_back_to_full_file_when_coverage_low(tmp_path):
    target = tmp_path / "large.py"
    target.write_text(
        "\n".join(f"LINE {i}" for i in range(1, 501)),
        encoding="utf-8",
    )

    terrain = SimpleNamespace(
        sources=[SimpleNamespace(line=10)],
        sinks=[SimpleNamespace(line=20)],
    )
    agent = Agent1e(model="gpt-4o", repo_path=tmp_path)
    content = await agent._read_focused_source(str(target), terrain)

    assert "LINE 500" in content
    assert "# Lines " not in content


@pytest.mark.asyncio
async def test_focused_source_keeps_excerpts_when_coverage_sufficient(tmp_path):
    target = tmp_path / "medium.py"
    target.write_text(
        "\n".join(f"LINE {i}" for i in range(1, 201)),
        encoding="utf-8",
    )

    terrain = SimpleNamespace(
        sources=[SimpleNamespace(line=50)],
        sinks=[SimpleNamespace(line=150)],
    )
    agent = Agent1e(model="gpt-4o", repo_path=tmp_path)
    content = await agent._read_focused_source(str(target), terrain)

    assert "# Lines " in content
    assert "LINE 150" in content
    assert "LINE 200" not in content
