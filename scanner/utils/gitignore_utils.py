"""
Shared .gitignore parsing and matching helpers.

These are deliberately lightweight approximations of git's matching rules:
they cover the common cases (literal names, ``*`` globs, directory entries,
anchored ``/`` entries and ``!`` negation) — enough for security auditing,
without re-implementing the full gitignore spec.
"""
from __future__ import annotations
import fnmatch
from pathlib import Path
from typing import Set, Tuple


def parse_gitignore(path: Path) -> Tuple[Set[str], Set[str]]:
    """Return ``(ignore_patterns, negated_patterns)`` from a .gitignore file.

    Negation lines (``!pattern``) are returned separately so callers can
    correctly treat re-included paths (e.g. ``!.env.example``) as NOT ignored.
    """
    patterns: Set[str] = set()
    negations: Set[str] = set()
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return patterns, negations

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            negations.add(line[1:].strip())
        else:
            patterns.add(line)
    return patterns, negations


def _norm(pattern: str) -> str:
    """Normalise a pattern/path for fnmatch comparison."""
    return pattern.strip().lstrip("/").rstrip("/")


def _matches_any(rel_path: str, name: str, pattern_set: Set[str]) -> bool:
    for raw in pattern_set:
        pat = _norm(raw)
        if not pat:
            continue
        # gitignore matches at any directory depth unless anchored, so test the
        # full relative path, the bare filename, nested forms, and each segment.
        if (
            fnmatch.fnmatch(rel_path, pat)
            or fnmatch.fnmatch(name, pat)
            or fnmatch.fnmatch(rel_path, f"*/{pat}")
            or fnmatch.fnmatch(rel_path, f"{pat}/*")
            or fnmatch.fnmatch(rel_path, f"*/{pat}/*")
            or any(fnmatch.fnmatch(seg, pat) for seg in rel_path.split("/"))
        ):
            return True
    return False


def path_is_ignored(rel_path: str, patterns: Set[str], negations: Set[str] | None = None) -> bool:
    """Best-effort: would ``rel_path`` be ignored by these gitignore patterns?

    ``rel_path`` is normalised to forward slashes and made relative to the repo
    root by the caller. A path is ignored if it matches a positive pattern and
    is not re-included by a negation pattern.
    """
    negations = negations or set()
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    name = rel_path.rsplit("/", 1)[-1]

    if _matches_any(rel_path, name, patterns):
        return not _matches_any(rel_path, name, negations)
    return False


def pattern_is_covered(required: str, patterns: Set[str]) -> bool:
    """Is a *recommended* gitignore pattern (e.g. ``*.pem``) already covered?

    This compares pattern-against-pattern (not a concrete file path): a required
    pattern is covered if an existing entry is identical, broader, or otherwise
    matches it.
    """
    clean = _norm(required)
    for raw in patterns:
        entry = _norm(raw)
        if not entry:
            continue
        if entry == clean:
            return True
        # An existing broader entry (e.g. ``.env*``) covers ``.env`` / ``.env.*``.
        if fnmatch.fnmatch(clean, entry):
            return True
        # A wildcard requirement (e.g. ``*.tfstate``) is covered by a matching entry.
        if "*" in clean and fnmatch.fnmatch(entry, clean):
            return True
    return False
