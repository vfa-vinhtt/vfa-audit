"""
Plugin: ENV Checker
Detects .env files and decides how exposed they are by combining three signals:
  - is the file actually committed to git (or, with no git data, un-ignored)?
  - does it contain real values (vs. a placeholder template)?
  - is it an example/sample template (expected to be committed)?

It also flags source code that reads environment variables when no .env / .env.example
exists, which usually means onboarding is undocumented.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Optional, Set

from .base_plugin import BasePlugin, Finding, Severity
from ..utils.gitignore_utils import parse_gitignore, path_is_ignored

# Source file extensions worth scanning for env-var access. The actual access
# patterns are owned by each language adapter (BaseAdapter.ENV_ACCESS_PATTERNS)
# and aggregated at runtime, so this list lives in one place per language.
SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".kts", ".cs", ".php", ".go", ".rb",
    ".swift", ".m", ".mm",
}

# Substrings that mark a value as a placeholder rather than a real secret.
_PLACEHOLDER_MARKERS = (
    "your_", "your-", "changeme", "change_me", "placeholder", "example",
    "todo", "replace", "dummy", "sample", "xxxx", "<", "{", "$",
)


def _is_populated_env_line(line: str) -> bool:
    """True if a line assigns a real (non-placeholder) value to an env var.

    Accepts both UPPER_CASE and lower-case keys (real .env files use both).
    """
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return False
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip().strip('"').strip("'").strip()
    if not value:
        return False
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", key):
        return False
    low = value.lower()
    if any(marker in low for marker in _PLACEHOLDER_MARKERS):
        return False
    return True


def _mask_env_line(line: str) -> str:
    """Mask the value half of a KEY=value line for safe evidence display."""
    key, sep, value = line.partition("=")
    value = value.strip()
    if len(value) <= 4:
        masked = "*" * len(value)
    else:
        masked = value[:2] + "***REDACTED***"
    return f"{key.rstrip()}{sep}{masked}"


class EnvChecker(BasePlugin):
    name = "env_checker"
    description = "Detects .env files and verifies they are not exposed in git"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []

        gi_path = root / ".gitignore"
        patterns, negations = parse_gitignore(gi_path) if gi_path.exists() else (set(), set())
        is_repo = context.get("is_git_repo", False)
        tracked = context.get("git_tracked_files", set())

        env_files_found = []
        for f in files:
            name = f.name
            if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
                env_files_found.append(f)
                self._check_env_file(f, root, patterns, negations, is_repo, tracked)

        self._check_env_usage_in_source(files, env_files_found, context)

        if not env_files_found:
            self.add_finding(
                severity=Severity.INFO,
                title="No .env files found",
                description=(
                    "No .env files were detected. If environment variables are used, "
                    "ensure a .env.example template exists for onboarding."
                ),
                recommendation=(
                    "Create a .env.example with all required variable names "
                    "(no real values) and commit it to source control."
                ),
                tags=["env", "documentation"],
            )

        return self.findings

    def _check_env_file(
        self, path: Path, root: Path,
        patterns: Set[str], negations: Set[str],
        is_repo: bool, tracked: Set[str],
    ) -> None:
        rel = str(path.relative_to(root))
        rel_posix = rel.replace("\\", "/")
        name_lower = path.name.lower()
        is_example = "example" in name_lower or "sample" in name_lower

        lines = self._read_lines(path)
        populated = [(i + 1, ln) for i, ln in enumerate(lines) if _is_populated_env_line(ln)]
        is_populated = bool(populated)
        evidence: Optional[str] = _mask_env_line(populated[0][1]) if populated else None

        # Example/template files are meant to be committed — only warn if one looks
        # like it accidentally holds real values.
        if is_example:
            if is_populated:
                self.add_finding(
                    severity=Severity.MEDIUM,
                    title=f"Example env file appears to contain real values: {rel}",
                    description=(
                        f"'{rel}' is an example/template, but {len(populated)} line(s) look like "
                        "real values rather than placeholders. Templates should never hold secrets."
                    ),
                    recommendation="Replace real values with placeholders (e.g. YOUR_API_KEY_HERE).",
                    file=rel,
                    line=populated[0][0],
                    evidence=evidence,
                    tags=["env", "documentation"],
                )
            return

        ignored = path_is_ignored(rel_posix, patterns, negations)
        committed = rel_posix in tracked

        if is_repo and committed:
            severity = Severity.CRITICAL if is_populated else Severity.HIGH
            value_note = (
                f" It contains {len(populated)} real value(s)." if is_populated
                else " It currently looks template-like, but it is still tracked."
            )
            self.add_finding(
                severity=severity,
                title=f".env file committed to git: {rel}",
                description=(
                    f"'{rel}' is tracked by git, so its contents are in the repository "
                    f"history and visible to anyone with access.{value_note}"
                ),
                recommendation=(
                    f"1. Run: git rm --cached {rel}\n"
                    "2. Add '.env' and '.env.*' to .gitignore (keep '!.env.example').\n"
                    "3. Rotate every credential the file contained — it stays in history.\n"
                    "4. Consider scrubbing history with git filter-repo or BFG."
                ),
                file=rel,
                line=populated[0][0] if populated else None,
                evidence=evidence,
                tags=["env", "secret", "git-tracked"],
            )
        elif not ignored:
            severity = Severity.CRITICAL if is_populated else Severity.HIGH
            self.add_finding(
                severity=severity,
                title=f".env file not covered by .gitignore: {rel}",
                description=(
                    f"'{rel}' is not matched by any .gitignore rule"
                    + (" and contains real values" if is_populated else "")
                    + ". It would be committed on the next `git add`, exposing credentials."
                ),
                recommendation=(
                    "Add the following to your .gitignore:\n"
                    "  .env\n  .env.*\n  !.env.example\n  !.env.sample"
                ),
                file=rel,
                line=populated[0][0] if populated else None,
                evidence=evidence,
                tags=["env", "gitignore"],
            )
        elif is_populated:
            # Ignored by git but real values sit on disk — low risk, worth noting.
            self.add_finding(
                severity=Severity.INFO,
                title=f"Local .env with real values (properly gitignored): {rel}",
                description=(
                    f"'{rel}' contains {len(populated)} real value(s) but is correctly ignored by "
                    "git, so it will not be committed. This is the expected setup for local secrets."
                ),
                recommendation="Ensure teammates create their own .env from .env.example.",
                file=rel,
                tags=["env", "gitignore"],
            )
        else:
            self.add_finding(
                severity=Severity.INFO,
                title=f".env file is properly gitignored: {rel}",
                description=f"'{rel}' is correctly ignored by git.",
                recommendation="Ensure teammates create their own .env from .env.example.",
                file=rel,
                tags=["env", "gitignore"],
            )

    def _check_env_usage_in_source(self, files: List[Path], env_files: list, context: dict) -> None:
        if env_files:
            return  # a .env / template exists, onboarding is presumably documented

        patterns = self._env_access_patterns(context)
        if not patterns:
            return

        uses_env_vars = False
        for f in files:
            if f.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            content = "\n".join(self._read_lines(f))
            if any(re.search(pattern, content) for pattern, _ in patterns):
                uses_env_vars = True
                break

        if uses_env_vars:
            self.add_finding(
                severity=Severity.MEDIUM,
                title="Environment variables accessed but no .env file found",
                description=(
                    "Source code accesses environment variables (os.getenv, process.env, etc.) "
                    "but no .env file or .env.example exists."
                ),
                recommendation=(
                    "Create a .env.example listing all required variable names "
                    "and document their purpose for other developers."
                ),
                tags=["env", "documentation"],
            )

    def _env_access_patterns(self, context: dict):
        """Aggregate (regex, label) env-access patterns from the detected adapters.

        Patterns are owned by each language adapter, so only languages actually
        present contribute. Falls back to every known adapter's patterns when no
        adapter was detected (e.g. a manifest-less repo) so the heuristic still works.
        """
        patterns = []
        seen = set()
        for inst in context.get("adapter_instances", []):
            for pat, label in getattr(inst, "ENV_ACCESS_PATTERNS", []):
                if pat not in seen:
                    seen.add(pat)
                    patterns.append((pat, label))
        return patterns or self._all_adapter_patterns()

    @staticmethod
    def _all_adapter_patterns():
        """Discover ENV_ACCESS_PATTERNS from every adapter class (DRY fallback)."""
        import importlib
        import pkgutil
        import scanner.adapters
        from scanner.adapters.base_adapter import BaseAdapter

        patterns = []
        seen = set()
        for _, mod_name, _ in pkgutil.iter_modules(scanner.adapters.__path__):
            if mod_name == "base_adapter":
                continue
            try:
                module = importlib.import_module(f"scanner.adapters.{mod_name}")
            except Exception:
                continue
            for item in dir(module):
                obj = getattr(module, item)
                if isinstance(obj, type) and issubclass(obj, BaseAdapter) and obj is not BaseAdapter:
                    for pat, label in getattr(obj, "ENV_ACCESS_PATTERNS", []):
                        if pat not in seen:
                            seen.add(pat)
                            patterns.append((pat, label))
        return patterns
