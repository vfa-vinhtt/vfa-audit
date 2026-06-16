"""
Base adapter interface for language-specific dependency/project parsers.
"""
from __future__ import annotations
import abc
import re
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple

from ..plugins.base_plugin import Finding, Severity
# Single source of truth for license normalization/classification.
from ..utils.license_utils import _normalize_license, _classify_license


class BaseAdapter(abc.ABC):
    """Extracts language-specific dependency and project metadata."""

    name: str = "base"

    # Language/framework-specific (regex, label) patterns for detecting environment
    # variable access in source code. Concrete adapters override this; the env_checker
    # plugin aggregates patterns only for the languages actually detected, so each
    # language's knowledge lives next to that language's adapter.
    ENV_ACCESS_PATTERNS: List[Tuple[str, str]] = []

    # Per-language directories to exclude from scanning (vendored deps, build output,
    # caches). Aggregated by the file scanner so language-specific ignores live with
    # the language; common/language-agnostic dirs are configured in config.yaml.
    IGNORE_DIRS: Set[str] = set()

    # External CLI tools this adapter needs, keyed by purpose:
    #   "audit"   -> dependency vulnerability auditing  (dependency_checker.project_audit)
    #   "license" -> native license resolution          (license_checker.project_tool)
    # Value is (command_to_check_on_PATH, install_hint). Used by the pre-scan
    # requirements check so missing tooling is reported up front.
    REQUIRED_TOOLS: Dict[str, Tuple[str, str]] = {}

    def __init__(self, root: Path):
        self.root = root

    @staticmethod
    def _clean_version(version: str) -> str:
        """Strip version-range prefixes for display (^4.1.0 -> 4.1.0, v1.9.1 -> 1.9.1).
        Returns '' for non-versions like *, latest, UNKNOWN so callers can omit them."""
        v = str(version or "").strip().lstrip("^~>=<v ").strip()
        return "" if v.upper() in ("", "*", "LATEST", "PROPERTY", "UNKNOWN") else v

    @abc.abstractmethod
    def detect(self) -> bool:
        """Return True if this adapter applies to the project."""
        ...

    @abc.abstractmethod
    def collect(self) -> Dict[str, Any]:
        """
        Return a dict with:
          - packages: Dict[name, version]
          - dependencies: Dict[name, {license, version}]
          - project_name: str
          - project_version: str
          - framework: str (optional)
        """
        ...

    def audit_dependencies(self) -> List[Finding]:
        """Run a language-specific dependency audit and return findings."""
        return []

    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        """Check dependency licenses using a dedicated tool. Adapters should override this."""
        return []

    # ── Shared helpers for license tooling ──────────────────────────────────

    def _evaluate_licenses(self, pairs: List[Tuple[str, str]], config: Dict) -> List[Finding]:
        """Classify (package, license) pairs against the configured policy.

        denied -> CRITICAL, classified-but-not-allowed -> HIGH, undetermined ->
        a single LOW summary. Shared by every adapter's check_licenses_with_tool()
        so the policy logic lives in one place and undetermined licenses don't flood
        the report (matching the license_checker content path).
        """
        denied = {c.upper() for c in config.get("deny", [])}
        allowed = set(config.get("allow_classifications", []))
        findings: List[Finding] = []
        undetermined: List[str] = []

        for pkg, license_str in pairs:
            lics = [l.strip() for l in re.split(r"OR|AND|[()/]", license_str or "") if l.strip()]
            if not lics:
                lics = [license_str or "UNKNOWN"]

            flagged = False
            for lic in lics:
                if _normalize_license(lic).upper() in denied:
                    findings.append(Finding(
                        plugin="license_checker", severity=Severity.CRITICAL,
                        title=f"Denied license: {pkg} ({lic})",
                        description=f"Package '{pkg}' uses a denied license '{lic}'.",
                        recommendation=f"Remove or replace '{pkg}' to comply with the license policy.",
                        tags=["license", self.name],
                    ))
                    flagged = True
                    break
                classification = _classify_license(lic)
                if classification in ("unknown", "no-license"):
                    continue
                if classification not in allowed:
                    findings.append(Finding(
                        plugin="license_checker", severity=Severity.HIGH,
                        title=f"Non-compliant license: {pkg} ({lic}) - {classification}",
                        description=f"Package '{pkg}' uses license '{lic}' classified as '{classification}'.",
                        recommendation="Review your license policy and consider replacing this dependency.",
                        tags=["license", self.name],
                    ))
                    flagged = True
                    break

            if not flagged and all(_classify_license(l) in ("unknown", "no-license") for l in lics):
                undetermined.append(pkg)

        if undetermined:
            sample = ", ".join(undetermined[:8])
            more = f" (+{len(undetermined) - 8} more)" if len(undetermined) > 8 else ""
            findings.append(Finding(
                plugin="license_checker", severity=Severity.LOW,
                title=f"{len(undetermined)} {self.name} dependencies with undetermined licenses",
                description=(
                    f"License metadata could not be determined for {len(undetermined)} package(s): "
                    f"{sample}{more}."
                ),
                recommendation="Verify these licenses manually or via the language's license tool.",
                tags=["license", self.name, "undetermined"],
            ))
        return findings

    def _tool_unavailable_finding(self, tool: str, install_hint: str, detail: str = "") -> Finding:
        """A LOW finding emitted when an optional native tool is missing/failed."""
        return Finding(
            plugin="license_checker", severity=Severity.LOW,
            title=f"{tool} not available for {self.name}",
            description=detail or f"The license tool '{tool}' was not found or failed to run.",
            recommendation=f"Install it to enable license resolution: {install_hint}",
            tags=["license", "tool-failure", self.name],
        )
