"""
Adapter: iOS / Swift (CocoaPods Podfile & Podfile.lock, Swift Package Manager Package.swift)

Covers both Objective-C and Swift projects, which share the same dependency
managers. Note: OSV has no CocoaPods/SwiftPM ecosystem, so vulnerability lookups
are skipped for these packages, but malicious-package, typosquat and license
checks still run.
"""
from __future__ import annotations
import csv
import io
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Any, List

from .base_adapter import BaseAdapter
from ..plugins.base_plugin import Finding, Severity

GHSA_ADVISORIES_API = "https://api.github.com/advisories"


class SwiftAdapter(BaseAdapter):
    name = "swift"
    license_tool_name = "license_finder"
    project_audit_tool_name = "ghsa"
    IGNORE_DIRS = {"Pods", ".build", "Carthage", "DerivedData"}

    ENV_ACCESS_PATTERNS = [
        (r"ProcessInfo\.processInfo\.environment", "Swift ProcessInfo.environment"),
        (r"\bgetenv\s*\(", "Obj-C / Swift getenv()"),
    ]

    # Audit uses the GitHub Advisory DB over the network (no binary required).
    REQUIRED_TOOLS = {
        "license": ("license_finder", "gem install license_finder"),
    }

    def detect(self) -> bool:
        return any([
            (self.root / "Package.swift").exists(),
            (self.root / "Podfile").exists(),
            (self.root / "Podfile.lock").exists(),
            bool(list(self.root.glob("*.xcodeproj"))),
            bool(list(self.root.glob("*.xcworkspace"))),
        ])

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {"swift": {}},
            "dependencies": {},
            "project_name": self.root.name,
            "project_version": "",
            "framework": "",
        }

        packages: Dict[str, str] = {}
        packages.update(self._parse_podfile())
        packages.update(self._parse_package_swift())
        # Exact versions from the lock file take precedence where available.
        packages.update(self._parse_podfile_lock(packages))

        # Project name from the .xcodeproj bundle, if present.
        xcodeprojs = list(self.root.glob("*.xcodeproj"))
        if xcodeprojs:
            result["project_name"] = xcodeprojs[0].stem

        result["packages"]["swift"] = packages
        result["dependencies"] = {
            name: {"version": ver, "license": "UNKNOWN"} for name, ver in packages.items()
        }

        if (self.root / "Podfile").exists() or (self.root / "Podfile.lock").exists():
            result["framework"] = "CocoaPods"
        elif (self.root / "Package.swift").exists():
            result["framework"] = "Swift Package Manager"

        return result

    def _parse_podfile(self) -> Dict[str, str]:
        podfile = self.root / "Podfile"
        if not podfile.exists():
            return {}
        try:
            content = podfile.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return {}
        packages: Dict[str, str] = {}
        # pod 'Alamofire', '~> 5.6'   |   pod 'Firebase/Auth'
        pod_re = re.compile(r"""^\s*pod\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", re.MULTILINE)
        for m in pod_re.finditer(content):
            name = m.group(1).split("/")[0]  # drop subspec (Firebase/Auth -> Firebase)
            packages.setdefault(name, m.group(2) or "")
        return packages

    def _parse_podfile_lock(self, known: Dict[str, str]) -> Dict[str, str]:
        lock = self.root / "Podfile.lock"
        if not lock.exists():
            return {}
        try:
            lines = lock.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return {}
        versions: Dict[str, str] = {}
        in_pods = False
        # Under "PODS:" lines look like "  - Alamofire (5.6.4)"
        entry_re = re.compile(r"^\s+-\s+([^\s(/]+)(?:/[^\s(]+)?\s+\(([^)]+)\)")
        for raw in lines:
            if raw.startswith("PODS:"):
                in_pods = True
                continue
            if in_pods and raw and not raw.startswith(" "):
                break
            if in_pods:
                m = entry_re.match(raw)
                if m:
                    versions.setdefault(m.group(1), m.group(2))
        return versions

    def _parse_package_swift(self) -> Dict[str, str]:
        pkg_swift = self.root / "Package.swift"
        if not pkg_swift.exists():
            return {}
        try:
            content = pkg_swift.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return {}
        packages: Dict[str, str] = {}
        # .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.6.0")
        pkg_re = re.compile(r"""\.package\(\s*(?:name:\s*['"][^'"]+['"]\s*,\s*)?url:\s*['"]([^'"]+)['"]([^)]*)\)""")
        ver_re = re.compile(r"""['"](\d+\.\d+(?:\.\d+)?)['"]""")
        for m in pkg_re.finditer(content):
            url = m.group(1)
            name = url.rstrip("/").rsplit("/", 1)[-1]
            if name.endswith(".git"):
                name = name[:-4]
            ver_match = ver_re.search(m.group(2))
            packages.setdefault(name, ver_match.group(1) if ver_match else "")
        return packages

    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        """Resolve licenses with LicenseFinder (`license_finder report --format csv`).

        LicenseFinder is polyglot (CocoaPods / Carthage / SPM). It has no JSON output,
        so we use CSV with explicit columns. Degrades to a LOW finding when unavailable.
        """
        try:
            proc = subprocess.run(
                ["license_finder", "report", "--format", "csv", "--columns", "name", "licenses"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, cwd=str(self.root)
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return [self._tool_unavailable_finding(
                "license_finder", "gem install license_finder", str(e),
            )]

        if not (proc.stdout or "").strip():
            return []

        pairs = []
        for row in csv.reader(io.StringIO(proc.stdout)):
            if not row or not row[0].strip() or row[0].strip().lower() == "name":
                continue
            lic = ", ".join(c.strip() for c in row[1:] if c.strip()) or "UNKNOWN"
            pairs.append((row[0].strip(), lic))
        return self._evaluate_licenses(pairs, config)

    def audit_dependencies(self) -> List[Finding]:
        """Query the GitHub Advisory Database (GHSA) for the Swift ecosystem.

        GHSA identifies Swift packages by their SwiftPM URL (e.g.
        github.com/Alamofire/Alamofire), so this covers Package.swift dependencies.
        CocoaPods short names can't be mapped to GHSA identifiers and are skipped.
        Uses GITHUB_TOKEN / GH_TOKEN if present (higher rate limit); works unauthenticated.
        """
        identifiers = self._spm_identifiers()
        if not identifiers:
            return []

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM, "low": Severity.LOW,
        }
        findings: List[Finding] = []
        seen = set()

        for ident in identifiers[:30]:
            params = urllib.parse.urlencode({"ecosystem": "swift", "affects": ident, "per_page": "20"})
            req = urllib.request.Request(
                f"{GHSA_ADVISORIES_API}?{params}",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "security-scanner"},
            )
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    advisories = json.loads(resp.read())
            except (urllib.error.URLError, json.JSONDecodeError, OSError):
                continue

            for adv in advisories if isinstance(advisories, list) else []:
                gid = adv.get("ghsa_id", "")
                if not gid or gid in seen:
                    continue
                seen.add(gid)
                vrange = ""
                for v in (adv.get("vulnerabilities") or []):
                    if (v.get("package") or {}).get("name") == ident:
                        vrange = v.get("vulnerable_version_range", "")
                        break
                cve = adv.get("cve_id") or gid
                summary = (adv.get("summary") or "GitHub security advisory.")[:200]
                findings.append(Finding(
                    plugin="dependency_checker:ghsa",
                    severity=sev_map.get((adv.get("severity") or "").lower(), Severity.MEDIUM),
                    title=f"Swift vulnerability in {ident.rsplit('/', 1)[-1]}: {cve}",
                    description=summary + (f" Affected range: {vrange}." if vrange else ""),
                    recommendation=f"Review {adv.get('html_url', '')} and upgrade to a patched version.",
                    evidence=ident,
                    tags=["dependency", "vulnerability", "swift", "ghsa"],
                ))
        return findings

    def _spm_identifiers(self) -> List[str]:
        """Extract GHSA-style identifiers (host/owner/repo) from Package.swift URLs."""
        pkg_swift = self.root / "Package.swift"
        if not pkg_swift.exists():
            return []
        try:
            content = pkg_swift.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        identifiers = []
        for m in re.finditer(r"""url:\s*['"]([^'"]+)['"]""", content):
            ident = re.sub(r"^https?://", "", m.group(1)).rstrip("/")
            if ident.endswith(".git"):
                ident = ident[:-4]
            if ident and ident not in identifiers:
                identifiers.append(ident)
        return identifiers
