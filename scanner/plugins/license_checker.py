from __future__ import annotations
import re
from pathlib import Path
from typing import List, Set, Dict, Any

from ..utils.license_utils import _normalize_license, _classify_license
from .base_plugin import BasePlugin, Finding, Severity
from ..core.trivy_adapter import run_trivy

LICENSE_FILE_NAMES = {"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYRIGHT"}


class LicenseChecker(BasePlugin):
    name = "license_checker"
    description = "Checks for license compliance"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        adapter_instances = context.get("adapter_instances", [])
        
        self._check_project_license(root)

        tools_config = self.config.get("tools", {})
        
        if tools_config.get("content"):
            for adapter in adapter_instances:
                deps = adapter.collect().get("dependencies", {})
                self._check_licenses_by_content(deps, self.config, adapter.name)

        if tools_config.get("trivy"):
            self._scan_with_trivy(root)

        if tools_config.get("project_tool"):
            for adapter in adapter_instances:
                tool_name = getattr(adapter, "license_tool_name", None)
                if not tool_name:
                    continue  # adapter has no dedicated license tool (e.g. Java)
                tool_findings = adapter.check_licenses_with_tool(self.config)
                # Group every result under the tool so the report shows it ran
                # (e.g. license_checker:pip-licenses), mirroring secret_checker's tools.
                for f in tool_findings:
                    f.plugin = f"license_checker:{tool_name}"
                if tool_findings:
                    self.findings.extend(tool_findings)
                else:
                    # Tool ran and found no policy violations -> confirm execution.
                    self.findings.append(Finding(
                        plugin=f"license_checker:{tool_name}",
                        severity=Severity.INFO,
                        title=f"{tool_name} license check completed - no policy violations",
                        description=f"'{tool_name}' ran successfully and found no license policy violations.",
                        recommendation="No action needed; the license tool executed successfully.",
                        tags=["license", tool_name, "scan-summary"],
                    ))

        return self.findings

    def _scan_with_trivy(self, root: Path) -> None:
        """Run Trivy --license-full scan to catch licenses that adapters might miss
        (e.g. packages whose manifests don't declare a license, or vendored code).
        """
        original_name = self.name
        self.name = "license_checker:trivy"
        try:
            result = run_trivy(root, "license", license_full=True)
        except RuntimeError:
            self.add_finding(
                severity=Severity.WARNING,
                title="Trivy license scan failed: tool not found",
                description="trivy was configured but not found on PATH.",
                recommendation=(
                    "brew install trivy | scoop install trivy | "
                    "winget install Aquasecurity.Trivy"
                ),
                tags=["tool-failure", "trivy"],
            )
            self.name = original_name
            return

        if result is None:
            self.add_finding(
                severity=Severity.WARNING,
                title="Trivy license scan failed",
                description="Trivy ran but produced no output.",
                recommendation="Ensure trivy is installed and functioning correctly.",
                tags=["tool-failure", "trivy"],
            )
            self.name = original_name
            return

        denied = set(c.upper() for c in self.config.get("deny", []))
        allowed_class = set(self.config.get("allow_classifications", []))

        flagged_count = 0
        for res in result.get("Results") or []:
            for lic in res.get("Licenses") or []:
                pkg = lic.get("PkgName") or lic.get("FilePath") or "?"
                name = lic.get("Name") or ""
                category = (lic.get("Category") or "").lower()
                norm_name = _normalize_license(name).upper()

                if norm_name in denied or category == "forbidden":
                    self.add_finding(
                        severity=Severity.CRITICAL,
                        title=f"Denied license: {pkg} ({name})",
                        description=(
                            f"Package '{pkg}' uses a denied license '{name}' "
                            f"(Trivy category: {category or 'N/A'})."
                        ),
                        recommendation=f"Remove or replace '{pkg}' to comply with the license policy.",
                        tags=["license", "trivy", "denied"],
                    )
                    flagged_count += 1
                    continue

                classification = _classify_license(name)
                if category in ("restricted", "reciprocal") or (
                    classification not in allowed_class
                    and classification not in ("no-license", "unknown")
                ):
                    self.add_finding(
                        severity=Severity.HIGH,
                        title=f"Non-compliant license: {pkg} ({name}) - {classification or category}",
                        description=(
                            f"Package '{pkg}' uses license '{name}' "
                            f"(classification: '{classification}', Trivy category: '{category}')."
                        ),
                        recommendation=(
                            "Review your project's license policy and consider replacing this dependency."
                        ),
                        tags=["license", "trivy", classification or category],
                    )
                    flagged_count += 1
                elif category == "unknown" or classification == "unknown":
                    self.add_finding(
                        severity=Severity.MEDIUM,
                        title=f"Undetermined license: {pkg} ({name or 'UNKNOWN'})",
                        description=(
                            f"Package '{pkg}' has an undetermined license '{name}' "
                            "that could not be classified."
                        ),
                        recommendation=(
                            "Manually verify the license is compatible with your use case."
                        ),
                        tags=["license", "trivy", "unknown"],
                    )
                    flagged_count += 1

        if flagged_count == 0:
            self.add_finding(
                severity=Severity.INFO,
                title="Trivy license scan completed - no policy violations",
                description="Trivy --license-full scan found no denied or restricted licenses.",
                recommendation="No action needed.",
                tags=["license", "trivy", "scan-summary"],
            )
        self.name = original_name

    def _check_licenses_by_content(self, deps: Dict[str, Any], config: Dict, adapter_name: str):
        denied = set(c.upper() for c in config.get("deny", []))
        allowed_class = set(config.get("allow_classifications", []))
        undetermined = []

        for pkg, info in deps.items():
            license_str = info.get("license", "UNKNOWN")
            if isinstance(license_str, list):
                license_str = ", ".join(license_str) or "UNKNOWN"
            licenses = [l.strip() for l in re.split(r'OR|AND|[()/]', license_str) if l.strip()]
            if not licenses: licenses = [license_str]

            flagged = False
            for lic in licenses:
                norm_lic = _normalize_license(lic).upper()
                if norm_lic in denied:
                    self.add_finding(
                        severity=Severity.CRITICAL,
                        title=f"Denied license: {pkg} ({lic})",
                        description=f"Package '{pkg}' uses a denied license '{lic}'.",
                        recommendation=f"Remove or replace the dependency '{pkg}' to comply with the license policy.",
                        tags=[adapter_name]
                    )
                    flagged = True
                    break

                classification = _classify_license(lic)
                # Undetermined licenses can't be judged — usually it just means the
                # dependency isn't installed / no license tool ran, NOT a real policy
                # violation. Collect them for a single summary instead of one HIGH each.
                if classification in ("unknown", "no-license"):
                    continue
                if classification not in allowed_class:
                    self.add_finding(
                        severity=Severity.HIGH,
                        title=f"Non-compliant license: {pkg} ({lic}) - {classification}",
                        description=f"Package '{pkg}' uses license '{lic}' which is classified as '{classification}'.",
                        recommendation="Review your project's license policy and consider replacing this dependency.",
                        tags=[adapter_name]
                    )
                    flagged = True
                    break

            if not flagged and all(
                _classify_license(l) in ("unknown", "no-license") for l in licenses
            ):
                undetermined.append(pkg)

        if undetermined:
            sample = ", ".join(undetermined[:8])
            more = f" (+{len(undetermined) - 8} more)" if len(undetermined) > 8 else ""
            self.add_finding(
                severity=Severity.LOW,
                title=f"{len(undetermined)} {adapter_name} dependencies with undetermined licenses",
                description=(
                    f"License metadata could not be determined for {len(undetermined)} {adapter_name} "
                    f"package(s): {sample}{more}. This usually means dependencies are not installed "
                    "or no license tool is available — not that the licenses are non-compliant."
                ),
                recommendation=(
                    "Install dependencies and run a license tool (e.g. pip-licenses, license-checker) "
                    "to resolve licenses, or record them manually for compliance."
                ),
                tags=[adapter_name, "license", "undetermined"]
            )

    def _check_project_license(self, root: Path):
        if not any((root / name).exists() for name in LICENSE_FILE_NAMES):
            self.add_finding(
                severity=Severity.HIGH,
                title="No LICENSE file in project root",
                description="A project without a license is 'All Rights Reserved' by default.",
                recommendation="Add a LICENSE file (e.g., MIT, Apache-2.0) to the project root.",
            )
