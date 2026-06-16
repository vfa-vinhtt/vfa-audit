"""
Core file scanner — recursive directory traversal with ignore support.
"""
from __future__ import annotations
import os
import fnmatch
from pathlib import Path
from typing import List, Set, Tuple

# Extensions considered binary / non-scannable for text patterns
BINARY_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc", ".pyo",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".jar", ".war", ".ear",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".tiff", ".webp",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".db", ".sqlite", ".sqlite3",
}

FONT_EXTENSIONS: Set[str] = {".ttf", ".otf", ".woff", ".woff2", ".eot"}
IMAGE_EXTENSIONS: Set[str] = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                               ".tiff", ".webp", ".svg"}

# Minimal, always-on baseline (VCS dirs you must never scan). Per-language dirs
# (node_modules, vendor, target, Pods, bin/obj, ...) are declared by each adapter's
# IGNORE_DIRS and merged in by main.py; language-agnostic dirs (dist, build, coverage,
# .idea, ...) are configured under file_scanner.ignore_dirs in config.yaml.
DEFAULT_IGNORE_DIRS: Set[str] = {".git", ".svn", ".hg"}


class FileScanner:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self._ignore_dirs: Set[str] = DEFAULT_IGNORE_DIRS | set(
            self.config.get("ignore_dirs", [])
        )
        self._ignore_patterns: List[str] = self.config.get("ignore_patterns", [])
        self._gitignore_patterns: List[str] = []

    def load_gitignore(self, root: Path) -> None:
        gitignore = root / ".gitignore"
        if gitignore.exists():
            for line in gitignore.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self._gitignore_patterns.append(line)

    def _is_ignored(self, path: Path, root: Path) -> bool:
        rel = path.relative_to(root)
        parts = rel.parts

        # Check directory components
        for part in parts:
            if part in self._ignore_dirs:
                return True

        # Check custom (user-configured) patterns only. .gitignore patterns are
        # intentionally NOT used for pruning: the scanner must still inspect files
        # that should have been ignored (e.g. a committed .env). They are loaded via
        # load_gitignore() solely to expose coverage info to plugins.
        rel_str = str(rel)
        for pattern in self._ignore_patterns:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True

        return False

    def scan(self, root: Path) -> Tuple[List[Path], List[Path], List[Path]]:
        """
        Returns (text_files, asset_files, all_files) relative to root.
        """
        text_files: List[Path] = []
        asset_files: List[Path] = []
        all_files: List[Path] = []

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            current = Path(dirpath)

            # Prune ignored directories in-place
            dirnames[:] = [
                d for d in dirnames
                if not self._is_ignored(current / d, root)
                and not (current / d).name.startswith(".")
                or (current / d).name in {".git"}  # keep .git for git scanner
            ]
            # Actually re-do: allow .git for git scanner
            pruned = []
            for d in dirnames:
                dp = current / d
                if d == ".git":
                    continue  # git scanner handles .git directly
                if self._is_ignored(dp, root):
                    continue
                pruned.append(d)
            dirnames[:] = pruned

            for fname in filenames:
                fpath = current / fname
                if self._is_ignored(fpath, root):
                    continue
                all_files.append(fpath)
                ext = fpath.suffix.lower()
                if ext in FONT_EXTENSIONS or ext in IMAGE_EXTENSIONS:
                    asset_files.append(fpath)
                elif ext not in BINARY_EXTENSIONS:
                    text_files.append(fpath)

        return text_files, asset_files, all_files

    @staticmethod
    def is_text_file(path: Path) -> bool:
        return path.suffix.lower() not in BINARY_EXTENSIONS

    @staticmethod
    def detect_language(root: Path) -> List[str]:
        """Detect programming languages used in the project."""
        markers = {
            "Python": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
            "Node.js": ["package.json"],
            "Java": ["pom.xml", "build.gradle", "build.gradle.kts"],
            ".NET": ["*.csproj", "*.sln", "packages.config"],
            "PHP": ["composer.json"],
            "Go": ["go.mod"],
            "Ruby": ["Gemfile"],
            "Rust": ["Cargo.toml"],
            "Swift": ["Package.swift", "*.xcodeproj", "*.xcworkspace",
                      "Podfile", "Podfile.lock", "*.podspec"],
            "Kotlin": ["*.kt", "*.kts"],
        }
        found = []
        for lang, files in markers.items():
            for pattern in files:
                if "*" in pattern:
                    if list(root.rglob(pattern)):
                        found.append(lang)
                        break
                elif (root / pattern).exists():
                    found.append(lang)
                    break
        return found or ["Unknown"]
