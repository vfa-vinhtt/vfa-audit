"""
Base plugin interface for all security scan plugins.
"""
from __future__ import annotations
import abc
import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


class Severity(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    WARNING = "WARNING"
    LOW = "LOW"
    INFO = "INFO"

    def color(self) -> str:
        return {
            "CRITICAL": "#c0392b",
            "HIGH": "#e67e22",
            "MEDIUM": "#f39c12",
            "WARNING": "#f1c40f",
            "LOW": "#2980b9",
            "INFO": "#7f8c8d",
        }[self.value]

    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 3, "LOW": 4, "INFO": 5}[self.value]


@dataclass
class Finding:
    severity: Severity
    plugin: str
    title: str
    description: str
    recommendation: str
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    # Other sub-tools that flagged the SAME data point (set by the report engine's
    # cross-tool dedup). Presentation only — does not affect the finding's own plugin.
    also_detected_by: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "plugin": self.plugin,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "tags": self.tags,
            "also_detected_by": self.also_detected_by,
        }


class BasePlugin(abc.ABC):
    """Abstract base class for all scanner plugins."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.findings: List[Finding] = []

    def add_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        recommendation: str,
        file: str = None,
        line: int = None,
        evidence: str = None,
        tags: List[str] = None,
    ) -> None:
        self.findings.append(
            Finding(
                severity=severity,
                plugin=self.name,
                title=title,
                description=description,
                recommendation=recommendation,
                file=file,
                line=line,
                evidence=self._truncate(evidence),
                tags=tags or [],
            )
        )

    @staticmethod
    def _truncate(text: str, max_len: int = 200) -> Optional[str]:
        if text is None:
            return None
        text = text.strip()
        return text[:max_len] + "…" if len(text) > max_len else text

    @abc.abstractmethod
    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        """Run the plugin scan and return findings."""
        ...

    def _read_lines(self, path: Path) -> List[str]:
        """Safely read file lines, skipping binary files."""
        try:
            return path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []
