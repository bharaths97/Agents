from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


class RepoResolveError(RuntimeError):
    """Raised when repository input cannot be resolved to a local directory."""


@dataclass(frozen=True)
class ResolvedRepo:
    repo_path: Path
    source: str  # "local" | "cloned"
    repo_url: str | None = None
    branch: str | None = None
    commit: str | None = None
    reused_cache: bool = False


class RepoResolver:
    def __init__(
        self,
        cache_root: Path,
        clone_timeout_sec: int = 180,
        clone_max_attempts: int = 2,
        clone_depth: int = 1,
        git_binary: str = "git",
    ) -> None:
        self.cache_root = cache_root
        self.clone_timeout_sec = max(30, int(clone_timeout_sec))
        self.clone_max_attempts = max(1, int(clone_max_attempts))
        self.clone_depth = max(0, int(clone_depth))
        self.git_binary = git_binary

    def resolve(
        self,
        repo_path: Path | None,
        repo_url: str | None,
        branch: str | None = None,
        commit: str | None = None,
        refresh_clone: bool = False,
    ) -> ResolvedRepo:
        has_path = repo_path is not None
        has_url = bool(repo_url and repo_url.strip())
        if has_path == has_url:
            raise ValueError("Provide exactly one of --repo-path or --repo-url.")

        if repo_path is not None:
            resolved = repo_path.resolve()
            if not resolved.exists() or not resolved.is_dir():
                raise FileNotFoundError(
                    f"Repo path does not exist or is not a directory: {resolved}"
                )
            return ResolvedRepo(repo_path=resolved, source="local")

        assert repo_url is not None
        clean_url = self._normalize_repo_url(repo_url)
        clean_branch = branch.strip() if branch else None
        clean_commit = commit.strip() if commit else None

        self._ensure_git_available()
        clone_dir = self._clone_dir_for(clean_url, clean_branch)
        self.cache_root.mkdir(parents=True, exist_ok=True)

        if clone_dir.exists() and not refresh_clone and (clone_dir / ".git").is_dir():
            self._checkout_requested_ref(clone_dir, clean_commit)
            return ResolvedRepo(
                repo_path=clone_dir,
                source="cloned",
                repo_url=clean_url,
                branch=clean_branch,
                commit=clean_commit,
                reused_cache=True,
            )

        last_error: Exception | None = None
        for attempt in range(1, self.clone_max_attempts + 1):
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            try:
                self._clone_with_fallback(clean_url, clone_dir, clean_branch)
                self._checkout_requested_ref(clone_dir, clean_commit)
                self._verify_clone_nonempty(clone_dir)
                return ResolvedRepo(
                    repo_path=clone_dir,
                    source="cloned",
                    repo_url=clean_url,
                    branch=clean_branch,
                    commit=clean_commit,
                    reused_cache=False,
                )
            except Exception as exc:
                last_error = exc
                if clone_dir.exists():
                    shutil.rmtree(clone_dir, ignore_errors=True)
                if attempt < self.clone_max_attempts:
                    time.sleep(min(2 ** (attempt - 1), 5))

        raise RepoResolveError(f"Failed to clone repository after retries: {last_error}")

    def _ensure_git_available(self) -> None:
        try:
            self._run_git(["--version"], timeout_sec=10)
        except FileNotFoundError as exc:
            raise RepoResolveError(
                "git is required for --repo-url mode but is not installed or not on PATH."
            ) from exc
        except subprocess.SubprocessError as exc:
            raise RepoResolveError(f"Unable to execute git: {exc}") from exc

    def _clone_with_fallback(self, repo_url: str, clone_dir: Path, branch: str | None) -> None:
        shallow_cmd = ["clone", "--single-branch"]
        if branch:
            shallow_cmd += ["--branch", branch]
        if self.clone_depth > 0:
            shallow_cmd += ["--depth", str(self.clone_depth)]
        shallow_cmd += [repo_url, str(clone_dir)]

        try:
            self._run_git(shallow_cmd, timeout_sec=self.clone_timeout_sec)
            return
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").lower()
            if self.clone_depth <= 0 or not self._can_fallback_from_shallow(stderr):
                raise RepoResolveError(
                    f"git clone failed for {repo_url}: {self._format_git_error(exc)}"
                ) from exc

        full_cmd = ["clone", "--single-branch"]
        if branch:
            full_cmd += ["--branch", branch]
        full_cmd += [repo_url, str(clone_dir)]
        try:
            self._run_git(full_cmd, timeout_sec=self.clone_timeout_sec)
        except subprocess.CalledProcessError as exc:
            raise RepoResolveError(
                f"git clone fallback failed for {repo_url}: {self._format_git_error(exc)}"
            ) from exc

    def _checkout_requested_ref(self, clone_dir: Path, commit: str | None) -> None:
        if not commit:
            return
        try:
            self._run_git(["-C", str(clone_dir), "checkout", "--detach", commit], timeout_sec=60)
            return
        except subprocess.CalledProcessError:
            pass

        try:
            self._run_git(
                ["-C", str(clone_dir), "fetch", "--depth", "1", "origin", commit],
                timeout_sec=self.clone_timeout_sec,
            )
            self._run_git(["-C", str(clone_dir), "checkout", "--detach", commit], timeout_sec=60)
        except subprocess.CalledProcessError as exc:
            raise RepoResolveError(
                f"Unable to checkout requested commit '{commit}': {self._format_git_error(exc)}"
            ) from exc

    def _verify_clone_nonempty(self, clone_dir: Path) -> None:
        for child in clone_dir.iterdir():
            if child.name != ".git":
                return
        raise RepoResolveError(f"Cloned repository is empty: {clone_dir}")

    def _run_git(self, args: list[str], timeout_sec: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.git_binary, *args],
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout_sec,
        )

    @staticmethod
    def _normalize_repo_url(repo_url: str) -> str:
        clean_url = repo_url.strip()
        if not clean_url:
            raise ValueError("--repo-url cannot be empty.")
        looks_remote = "://" in clean_url or clean_url.startswith("git@")
        if not looks_remote:
            raise ValueError(
                "--repo-url must be a git URL (for local directories, use --repo-path)."
            )
        return clean_url

    @staticmethod
    def _can_fallback_from_shallow(stderr: str) -> bool:
        return "shallow" in stderr or "dumb http transport" in stderr

    def _clone_dir_for(self, repo_url: str, branch: str | None) -> Path:
        repo_name = repo_url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        safe_name = "".join(ch if (ch.isalnum() or ch in {"-", "_"}) else "-" for ch in repo_name)
        safe_name = safe_name.strip("-_") or "repo"
        key = hashlib.sha1(f"{repo_url}|{branch or ''}".encode("utf-8")).hexdigest()[:12]
        return self.cache_root / f"{safe_name}-{key}"

    @staticmethod
    def _format_git_error(exc: subprocess.CalledProcessError) -> str:
        stderr = (exc.stderr or "").strip()
        stdout = (exc.stdout or "").strip()
        if stderr:
            return stderr
        if stdout:
            return stdout
        return str(exc)
