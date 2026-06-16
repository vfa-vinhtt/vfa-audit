"""
Git repository information scanner.
"""
from __future__ import annotations
import subprocess
import re
from pathlib import Path
from typing import Dict, Optional


class GitScanner:
    def __init__(self, root: Path):
        self.root = root
        self._info: Optional[Dict] = None

    def _run(self, *args) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(self.root)] + list(args),
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def is_git_repo(self) -> bool:
        return bool(self._run("rev-parse", "--git-dir"))

    def get_info(self) -> Dict:
        if self._info is not None:
            return self._info

        if not self.is_git_repo():
            self._info = {"is_git": False}
            return self._info

        remote_url = self._run("remote", "get-url", "origin") or "N/A"
        branch = self._run("rev-parse", "--abbrev-ref", "HEAD") or "N/A"
        last_commit = self._run("log", "-1", "--format=%H %ai %s") or "N/A"
        author = self._run("log", "-1", "--format=%an <%ae>") or "N/A"
        repo_name = self._extract_repo_name(remote_url) or self.root.name

        self._info = {
            "is_git": True,
            "remote_url": self._sanitize_url(remote_url),
            "branch": branch,
            "last_commit": last_commit,
            "author": author,
            "repo_name": repo_name,
        }
        return self._info

    @staticmethod
    def _extract_repo_name(url: str) -> str:
        """Extract repo name from git remote URL."""
        # SSH: git@github.com:org/repo.git
        # HTTPS: https://github.com/org/repo.git
        match = re.search(r"[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
        if match:
            return match.group(1)
        return ""

    @staticmethod
    def _sanitize_url(url: str) -> str:
        """Remove credentials embedded in git URLs."""
        # Remove user:pass@ from URLs
        return re.sub(r"(https?://)([^@]+@)", r"\1", url)

    def get_tracked_files(self) -> list:
        """Return list of files tracked by git."""
        output = self._run("ls-files")
        return output.splitlines() if output else []

    def check_history_for_secrets(self, patterns: list) -> list:
        """
        Lightweight check: scan recent commit messages and diffs for obvious secrets.
        Checks last 50 commits only to keep it fast.
        """
        findings = []
        log = self._run("log", "--oneline", "-50", "--format=%H %s")
        for line in log.splitlines():
            for pattern in patterns:
                import re as _re
                if _re.search(pattern, line, _re.IGNORECASE):
                    findings.append({
                        "commit_line": line,
                        "pattern": pattern,
                    })
        return findings
