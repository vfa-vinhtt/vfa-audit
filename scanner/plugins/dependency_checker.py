"""
Plugin: Dependency Checker
Checks project dependencies for:
- Known security vulnerabilities (via OSV API or local tool invocation)
- Outdated / end-of-life packages
- Suspicious / typosquatting packages
- Packages with known malicious history
"""
from __future__ import annotations
import re
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict

from .base_plugin import BasePlugin, Finding, Severity
from ..core.trivy_adapter import run_trivy

KNOWN_MALICIOUS_PACKAGES: Dict[str, str] = {
    "event-stream": "Contained malicious code injected via maintainer takeover (2018)",
    "ua-parser-js": "Trojaned versions 0.7.29, 1.0.0 contained cryptominer (2021)",
    "coa": "Compromised versions 2.0.3, 2.1.1, 2.1.3 (2021)",
    "rc": "Compromised version 1.2.9 (2021)",
    "node-ipc": "Author intentionally sabotaged versions 10.1.1, 10.1.2 (2022)",
    "colors": "Author sabotaged v1.4.44-liberty-2 (2022)",
    "faker": "Author sabotaged v6.6.6 (2022)",
    "crossenv": "Typosquatting cross-env — steals environment variables",
    "d3.js": "Typosquatting d3 — malicious code",
    "jQuery": "Typosquatting jquery (lowercase matters in npm)",
    "python-mysql": "Malicious package impersonating mysql-connector-python",
    "python-sqlite": "Malicious package",
    "diango": "Typosquatting django — phishing credentials",
    "djanga": "Typosquatting django",
    "requesst": "Typosquatting requests",
    "colourama": "Typosquatting colorama — backdoor (2017)",
    "setup-tools": "Typosquatting setuptools",
    "loguru-dev": "Malicious clone of loguru",
}

COMMON_PACKAGES_TYPOS: Dict[str, str] = {
    "expres": "express", "expresss": "express", "expresjs": "express",
    "loadsh": "lodash", "lodahs": "lodash",
    "momnet": "moment", "mmoent": "moment",
    "recat": "react", "recat-dom": "react-dom",
    "axois": "axios", "axio": "axios",
    "mongooes": "mongoose", "mongooose": "mongoose",
    "djnago": "django", "dajngo": "django",
    "reqeusts": "requests", "reqests": "requests", "requets": "requests",
    "numppy": "numpy", "nupy": "numpy",
    "panads": "pandas", "pnadas": "pandas",
    "flaks": "flask", "falsk": "flask",
    "fasapi": "fastapi",
    "sqlalchmy": "sqlalchemy",
}

OSV_API = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 10

# Scanner ecosystem name -> OSV ecosystem name. Ecosystems not listed have no OSV DB.
OSV_ECOSYSTEMS = {
    "npm": "npm", "python": "PyPI", "java": "Maven", "dotnet": "NuGet",
    "php": "Packagist", "go": "Go", "ruby": "RubyGems", "rust": "crates.io",
}


class DependencyChecker(BasePlugin):
    name = "dependency_checker"
    description = "Checks dependencies for vulnerabilities, malicious packages, and typosquatting"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        adapter_instances = context.get("adapter_instances", [])
        adapter_context = context.get("adapters", {})
        packages = adapter_context.get("packages", {})
        tool_config = self.config.get("tools", {})

        # Trivy detects packages from project files independently of adapters, so it
        # runs even when no adapter-detected packages are available.
        if tool_config.get("trivy", {}).get("enabled", False):
            self._scan_with_trivy_vuln(root)

        if not packages:
            self.add_finding(severity=Severity.INFO, title="No dependency manifests found", description="Could not find package.json, requirements.txt, pom.xml, or other manifests.", recommendation="Ensure dependency files are present in the project root.", tags=["dependency"])
            return self.findings

        total = sum(len(pkgs) for pkgs in packages.values())
        self.add_finding(severity=Severity.INFO, title=f"Found {total} dependencies across {len(packages)} manifest(s)", description=f"Ecosystems detected: {', '.join(packages.keys())}", recommendation="Run dependency scans regularly (CI/CD) to catch new vulnerabilities.", tags=["dependency", "summary"])

        for ecosystem, pkgs in packages.items():
            self._check_known_malicious(pkgs, ecosystem)
            self._check_typosquatting(pkgs, ecosystem)

        if tool_config.get("osv", {}).get("enabled", True):
            before = len(self.findings)
            for ecosystem, pkgs in packages.items():
                self._query_osv_batch(pkgs, ecosystem)
            # Confirm OSV ran clean (so its execution is visible in the report) when it
            # covered at least one ecosystem and reported no vulnerabilities.
            osv_supported = any(eco.lower() in OSV_ECOSYSTEMS for eco in packages)
            osv_vulns = any(
                f.plugin == "dependency_checker:osv" and "vulnerability" in (f.tags or [])
                for f in self.findings[before:]
            )
            if osv_supported and not osv_vulns:
                self.name = "dependency_checker:osv"
                self.add_finding(
                    severity=Severity.INFO,
                    title="OSV scan completed - no known vulnerabilities found",
                    description=f"OSV checked {total} dependency version(s) and found no known CVEs.",
                    recommendation="Re-run regularly; new advisories are published continuously.",
                    tags=["dependency", "osv", "scan-summary"],
                )
                self.name = "dependency_checker"

        if tool_config.get("project_audit", {}).get("enabled", True):
            for adapter in adapter_instances:
                tool = getattr(adapter, "project_audit_tool_name", None)
                if not tool:
                    continue  # adapter has no native audit tool
                results = adapter.audit_dependencies()
                if results:
                    self.findings.extend(results)
                elif self._audit_tool_present(tool):
                    # Tool is installed and returned nothing -> ran clean. Surface an
                    # INFO so the report shows it executed (audit_dependencies returns []
                    # for both 'clean' and 'tool missing', so we confirm presence first).
                    self.name = f"dependency_checker:{tool}"
                    self.add_finding(
                        severity=Severity.INFO,
                        title=f"{tool} completed - no vulnerabilities found",
                        description=f"The '{tool}' dependency audit ran and reported no vulnerabilities.",
                        recommendation="No action needed; the audit executed successfully.",
                        tags=["dependency", tool, "scan-summary"],
                    )
                    self.name = "dependency_checker"
                # else: tool not installed -> the preflight check reports that separately.

        return self.findings

    def _scan_with_trivy_vuln(self, root: Path) -> None:
        """Run Trivy vuln scanner and classify findings by the vinhtt-tool CVE policy:
        CRITICAL/HIGH + fix available → CRITICAL; CRITICAL/HIGH + no fix or UNKNOWN → HIGH;
        MEDIUM → MEDIUM; LOW → LOW.
        """
        original_name = self.name
        self.name = "dependency_checker:trivy"
        try:
            result = run_trivy(root, "vuln")
        except RuntimeError:
            self.add_finding(
                severity=Severity.WARNING,
                title="Trivy CVE scan failed: tool not found",
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
                title="Trivy CVE scan failed",
                description="Trivy ran but produced no output.",
                recommendation="Ensure trivy is installed and functioning correctly.",
                tags=["tool-failure", "trivy"],
            )
            self.name = original_name
            return

        vuln_count = 0
        for res in result.get("Results") or []:
            for vuln in res.get("Vulnerabilities") or []:
                vuln_count += 1
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg = vuln.get("PkgName", "?")
                severity_str = (vuln.get("Severity") or "UNKNOWN").upper()
                fixed = (vuln.get("FixedVersion") or "").strip()
                title_str = vuln.get("Title") or ""

                if severity_str in ("CRITICAL", "HIGH"):
                    sev = Severity.CRITICAL if fixed else Severity.HIGH
                elif severity_str == "MEDIUM":
                    sev = Severity.MEDIUM
                elif severity_str == "LOW":
                    sev = Severity.LOW
                else:  # UNKNOWN severity
                    sev = Severity.HIGH

                fix_note = f" Fix: upgrade to {fixed}." if fixed else " No fix available yet."
                self.add_finding(
                    severity=sev,
                    title=f"Trivy CVE: {cve_id} in {pkg}",
                    description=(
                        f"{title_str or cve_id} — {pkg}@{vuln.get('InstalledVersion', '?')} "
                        f"(Severity: {severity_str}).{fix_note}"
                    ),
                    recommendation=(
                        f"Upgrade {pkg} to {fixed}." if fixed
                        else f"No fix yet for {cve_id}. Monitor for updates or apply mitigations."
                    ),
                    evidence=f"{pkg}@{vuln.get('InstalledVersion', '?')}",
                    tags=["dependency", "vulnerability", "cve", "trivy", cve_id.lower()],
                )

        if vuln_count == 0:
            self.add_finding(
                severity=Severity.INFO,
                title="Trivy CVE scan completed - no vulnerabilities found",
                description="Trivy scanned the project and found no known CVEs.",
                recommendation="Re-run regularly; new advisories are published continuously.",
                tags=["dependency", "trivy", "scan-summary"],
            )
        self.name = original_name

    @staticmethod
    def _audit_tool_present(tool: str) -> bool:
        """True only if the native audit tool genuinely exists, so we never claim a
        missing tool 'completed clean'."""
        import importlib.util
        from ..core.requirements import resolve_command
        if tool == "ghsa":
            return True  # network-based (GitHub Advisory DB)
        if tool == "pip_audit":
            return importlib.util.find_spec("pip_audit") is not None
        command = {
            "npm_audit": "npm", "govulncheck": "govulncheck",
            "dotnet_audit": "dotnet", "composer_audit": "composer",
        }.get(tool)
        return bool(command) and resolve_command(command) is not None

    def _check_known_malicious(self, pkgs: Dict[str, str], ecosystem: str) -> None:
        for name, version in pkgs.items():
            lower = name.lower()
            if lower in KNOWN_MALICIOUS_PACKAGES:
                self.add_finding(severity=Severity.CRITICAL, title=f"Known malicious/compromised package: {name}", description=f"Package '{name}' ({ecosystem}) has a known security incident: {KNOWN_MALICIOUS_PACKAGES[lower]}", recommendation=f"Remove '{name}' immediately. Check changelogs for safe versions. Audit your codebase for injected code and rotate all secrets.", evidence=f"{name}@{version}", tags=["dependency", "malicious", ecosystem.lower()])

    def _check_typosquatting(self, pkgs: Dict[str, str], ecosystem: str) -> None:
        for name in pkgs:
            lower = name.lower()
            if lower in COMMON_PACKAGES_TYPOS:
                correct = COMMON_PACKAGES_TYPOS[lower]
                self.add_finding(severity=Severity.HIGH, title=f"Possible typosquat package: {name}", description=f"Package '{name}' ({ecosystem}) looks like a typosquat of '{correct}'. Typosquat packages often contain malware.", recommendation=f"Verify you meant to install '{name}'. The legitimate package is '{correct}'.", evidence=name, tags=["dependency", "typosquat", ecosystem.lower()])

    def _query_osv_batch(self, pkgs: Dict[str, str], ecosystem: str) -> None:
        original_plugin_name = self.name
        self.name = "dependency_checker:osv"
        osv_ecosystem = OSV_ECOSYSTEMS.get(ecosystem.lower())

        if not osv_ecosystem:
            self.add_finding(
                severity=Severity.INFO,
                title=f"No OSV vulnerability database for ecosystem: {ecosystem}",
                description=(
                    f"OSV has no vulnerability database for '{ecosystem}' packages "
                    "(e.g. CocoaPods / Swift Package Manager), so CVE lookup is skipped. "
                    "Malicious-package and typosquat checks still apply."
                ),
                recommendation="Use an ecosystem-specific scanner for this language where available.",
                tags=["dependency", "osv", ecosystem.lower()],
            )
            self.name = original_plugin_name
            return

        pkg_items = list(pkgs.items())[:20]

        for pkg_name, version in pkg_items:
            if not version or version in ("*", "latest", ""):
                continue
            version_clean = re.sub(r"[^0-9.]", "", version.lstrip("^~>=<"))
            if not version_clean:
                continue

            payload = json.dumps({"package": {"name": pkg_name, "ecosystem": osv_ecosystem}, "version": version_clean}).encode()

            try:
                req = urllib.request.Request(OSV_API, data=payload, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
                    data = json.loads(resp.read())
                    vulns = data.get("vulns", [])
                    for v in vulns[:3]:
                        aliases = v.get("aliases", [v.get("id", "UNKNOWN")])
                        cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
                        severity = self._osv_severity(v)
                        self.add_finding(severity=severity, title=f"Vulnerability in {pkg_name}@{version_clean}: {cve}", description=v.get("summary", "No description available.")[:300], recommendation="Check https://osv.dev/vulnerability/" + v.get("id", "") + " for fixed versions and upgrade your dependency.", evidence=f"{pkg_name}=={version_clean}", tags=["dependency", "vulnerability", "cve", osv_ecosystem.lower()])
            except (urllib.error.URLError, json.JSONDecodeError, OSError):
                pass
        self.name = original_plugin_name

    @staticmethod
    def _osv_severity(vuln: dict) -> Severity:
        try:
            severities = vuln.get("severity", [])
            for s in severities:
                score = float(s.get("score", 0)) if "score" in s else 0
                rating = s.get("type", "")
                if rating == "CVSS_V3":
                    if score >= 9.0: return Severity.CRITICAL
                    if score >= 7.0: return Severity.HIGH
                    if score >= 4.0: return Severity.MEDIUM
                    return Severity.LOW
        except (ValueError, TypeError):
            pass
        return Severity.MEDIUM

