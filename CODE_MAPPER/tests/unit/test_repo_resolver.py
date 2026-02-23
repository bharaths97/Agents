import subprocess
from pathlib import Path

import pytest

from orchestrator.repo_resolver import RepoResolveError, RepoResolver


def test_resolve_local_repo_path(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("print('ok')", encoding="utf-8")

    resolver = RepoResolver(cache_root=tmp_path / "cache")
    resolved = resolver.resolve(repo_path=repo_dir, repo_url=None)

    assert resolved.source == "local"
    assert resolved.repo_path == repo_dir.resolve()


def test_resolve_requires_exactly_one_input(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    resolver = RepoResolver(cache_root=tmp_path / "cache")
    with pytest.raises(ValueError):
        resolver.resolve(repo_path=None, repo_url=None)
    with pytest.raises(ValueError):
        resolver.resolve(repo_path=repo_dir, repo_url="https://github.com/example/repo.git")


def test_repo_url_requires_git_available(tmp_path, monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("git missing")

    monkeypatch.setattr(subprocess, "run", fake_run)

    resolver = RepoResolver(cache_root=tmp_path / "cache")
    with pytest.raises(RepoResolveError, match="git is required"):
        resolver.resolve(repo_path=None, repo_url="https://github.com/example/repo.git")


def test_shallow_clone_fallback_to_full_clone(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def fake_run(cmd, text, capture_output, check, timeout):  # noqa: ANN001
        calls.append(cmd)
        if cmd[1:] == ["--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="git version 2.43.0", stderr="")

        if cmd[1] == "clone" and "--depth" in cmd:
            raise subprocess.CalledProcessError(
                returncode=128,
                cmd=cmd,
                output="",
                stderr="fatal: dumb http transport does not support shallow capabilities",
            )

        if cmd[1] == "clone":
            clone_target = Path(cmd[-1])
            clone_target.mkdir(parents=True, exist_ok=True)
            (clone_target / ".git").mkdir(parents=True, exist_ok=True)
            (clone_target / "README.md").write_text("ok", encoding="utf-8")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        raise AssertionError(f"Unexpected git command: {cmd}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    resolver = RepoResolver(cache_root=tmp_path / "cache", clone_max_attempts=1, clone_depth=1)
    resolved = resolver.resolve(repo_path=None, repo_url="https://github.com/example/repo.git")

    assert resolved.source == "cloned"
    clone_cmds = [cmd for cmd in calls if len(cmd) >= 2 and cmd[1] == "clone"]
    assert len(clone_cmds) == 2
    assert "--depth" in clone_cmds[0]
    assert "--depth" not in clone_cmds[1]


def test_cached_clone_reused_without_reclone(tmp_path, monkeypatch):
    repo_url = "https://github.com/example/repo.git"
    resolver = RepoResolver(cache_root=tmp_path / "cache")
    clone_dir = resolver._clone_dir_for(repo_url, branch=None)
    clone_dir.mkdir(parents=True, exist_ok=True)
    (clone_dir / ".git").mkdir(parents=True, exist_ok=True)
    (clone_dir / "main.py").write_text("print(1)", encoding="utf-8")

    calls: list[list[str]] = []

    def fake_run(cmd, text, capture_output, check, timeout):  # noqa: ANN001
        calls.append(cmd)
        if cmd[1:] == ["--version"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="git version 2.43.0", stderr="")
        raise AssertionError(f"Unexpected git command for cached clone: {cmd}")

    monkeypatch.setattr(subprocess, "run", fake_run)

    resolved = resolver.resolve(repo_path=None, repo_url=repo_url)

    assert resolved.source == "cloned"
    assert resolved.reused_cache is True
    assert resolved.repo_path == clone_dir
    assert all("clone" not in cmd for cmd in calls)
