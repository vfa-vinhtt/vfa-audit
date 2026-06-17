from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from .base_adapter import BaseAdapter
from ..plugins.base_plugin import Finding, Severity
from ..utils.license_utils import _classify_license

class NodeAdapter(BaseAdapter):
    name = "node"
    project_audit_tool_name = "npm_audit"
    license_tool_name = "license-checker"
    IGNORE_DIRS = {"node_modules", ".next", ".nuxt"}

    ENV_ACCESS_PATTERNS = [
        (r"process\.env\.", "Node.js process.env.X"),
        (r"process\.env\s*\[", "Node.js process.env[]"),
        (r"require\(\s*['\"]dotenv['\"]\s*\)", "Node dotenv require"),
        (r"import\s+[^\n;]*\bdotenv\b", "Node dotenv import"),
        (r"import\.meta\.env", "Vite import.meta.env"),
    ]

    REQUIRED_TOOLS = {
        "audit": ("npm", "https://nodejs.org/ (npm ships with Node.js)"),
        "license": ("license-checker", "npm install -g license-checker"),
    }

    def detect(self) -> bool:
        return (self.root / "package.json").exists()

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {"npm": {}},
            "dependencies": {},
            "project_name": "",
            "project_version": "",
            "framework": "",
        }

        pkg_json = self.root / "package.json"
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return result

        result["project_name"] = data.get("name", self.root.name)
        result["project_version"] = data.get("version", "0.0.0")

        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        deps.update(data.get("peerDependencies", {}))
        deps.update(data.get("optionalDependencies", {}))
        result["packages"]["npm"] = deps

        frameworks = {
            "react": "React", "vue": "Vue.js", "angular": "@angular/core",
            "next": "Next.js", "nuxt": "Nuxt.js", "svelte": "Svelte",
            "express": "Express", "fastify": "Fastify", "nestjs": "@nestjs/core",
            "electron": "Electron",
        }
        for key, label in frameworks.items():
            pkg = key if key in deps else (f"@{key}/core" if f"@{key}/core" in deps else None)
            if pkg:
                result["framework"] = f"{label} {self._clean_version(deps.get(pkg, ''))}".strip()
                break
        
        result["dependencies"] = self._collect_licenses(data, deps)
        return result

    def _collect_licenses(self, pkg_data: dict, deps: dict) -> dict:
        """Collects license information from lock files."""
        return self._extract_licenses_from_files(pkg_data, deps)

    def _extract_licenses_from_files(self, pkg_data: dict, deps: dict) -> dict:
        dep_info = {name: {"version": version, "license": "UNKNOWN"} for name, version in deps.items()}
        lock_file = self.root / "package-lock.json"
        if lock_file.exists():
            try:
                lock_data = json.loads(lock_file.read_text(encoding="utf-8"))
                packages = lock_data.get("packages", {})
                if packages:
                    for path, info in packages.items():
                        if not path: continue
                        name = path.split("node_modules/")[-1]
                        if name in dep_info:
                            lic = info.get("license", "UNKNOWN")
                            if isinstance(lic, list):
                                lic = ", ".join(lic) or "UNKNOWN"
                            dep_info[name]["license"] = lic
                    return dep_info
                dependencies = lock_data.get("dependencies", {})
                self._walk_npm_v1_lock(dependencies, dep_info)
                return dep_info
            except (json.JSONDecodeError, OSError):
                pass
        return dep_info
    
    def _walk_npm_v1_lock(self, node: dict, dep_info: dict):
        """Recursively walk the dependency tree of an npm v1 lock file."""
        for name, info in node.items():
            if name in dep_info:
                lic = info.get("license", "UNKNOWN")
                if isinstance(lic, list):
                    lic = ", ".join(lic) or "UNKNOWN"
                dep_info[name]["license"] = lic
            if "dependencies" in info:
                self._walk_npm_v1_lock(info["dependencies"], dep_info)

    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        if not (self.root / "node_modules").exists():
            return [Finding(
                plugin="license_checker",
                severity=Severity.LOW,
                title="Node.js dependencies not installed",
                description="The 'node_modules' directory was not found. The license checker tool requires dependencies to be installed.",
                recommendation="Run 'npm install' or 'yarn install' in the project directory before scanning.",
                tags=["license", "tool-failure", "node"],
            )]
        
        findings = []
        try:
            result = subprocess.run(
                ["license-checker", "--json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, cwd=self.root
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            # Tool failure finding
            return [Finding(
                plugin="license_checker",
                severity=Severity.LOW,
                title="Node.js license-checker tool failed",
                description=str(e),
                recommendation="Ensure 'license-checker' is installed (`npm install -g license-checker`) and accessible in your PATH.",
                tags=["license", "tool-failure", "node"],
            )]

        if result.returncode != 0 or not result.stdout:
            return []
            
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        denied = set(c.upper() for c in config.get("deny", []))
        allowed_class = set(config.get("allow_classifications", []))
        
        for name_ver, info in data.items():
            pkg_name = name_ver.rsplit('@', 1)[0]
            license_str = info.get("licenses", "UNKNOWN")
            if isinstance(license_str, list):
                license_str = ", ".join(license_str) or "UNKNOWN"

            licenses = [l.strip() for l in re.split(r'OR|AND|[()/]', license_str) if l.strip()]
            if not licenses: licenses = [license_str]

            for lic in licenses:
                if lic.upper() in denied:
                    findings.append(Finding(
                        plugin="license_checker",
                        severity=Severity.CRITICAL,
                        title=f"Denied license: {pkg_name} ({lic})",
                        description=f"Package '{pkg_name}' uses a denied license '{lic}'.",
                        recommendation=f"Remove or replace the dependency '{pkg_name}' to comply with the license policy.",
                        tags=["license", "dependency", "node"],
                    ))
                    break
                
                classification = _classify_license(lic)
                if classification not in allowed_class:
                    findings.append(Finding(
                        plugin="license_checker",
                        severity=Severity.HIGH,
                        title=f"Non-compliant license: {pkg_name} ({lic}) - {classification}",
                        description=f"Package '{pkg_name}' uses license '{lic}' which is classified as '{classification}'.",
                        recommendation="Review your project's license policy and consider replacing this dependency.",
                        tags=["license", "dependency", "node"],
                    ))
                    break
        return findings

    def audit_dependencies(self) -> List[Finding]:
        # (audit_dependencies implementation remains the same)
        if not (self.root / "package.json").exists():
            return []
        try:
            result = subprocess.run(
                ["npm", "audit", "--json", "--audit-level=moderate"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(self.root), timeout=60
            )
            if result.stdout:
                data = json.loads(result.stdout)
                vulns = data.get("vulnerabilities", {})
                if not vulns:
                    vulns = data.get("advisories", {})  # npm v6 format
                
                findings = []
                for pkg_name, vuln_data in vulns.items():
                    severity_str = vuln_data.get("severity", "unknown")
                    severity = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "moderate": Severity.MEDIUM, "low": Severity.LOW
                    }.get(severity_str.lower(), Severity.MEDIUM)
                    
                    fix = vuln_data.get("fixAvailable", {})
                    fix_str = f"Fix: {fix.get('name')}@{fix.get('version')}" if isinstance(fix, dict) else "Run 'npm audit fix'"
                    
                    via = [v['name'] if isinstance(v, dict) else v for v in vuln_data.get("via", [])]
                    via_str = f" (via {', '.join(via)})" if via else ""

                    findings.append(Finding(
                        plugin=f"dependency_checker:{self.project_audit_tool_name}",
                        severity=severity,
                        title=f"npm vulnerability: {pkg_name}{via_str}",
                        description=f"Package '{pkg_name}' has a {severity_str} vulnerability.",
                        recommendation=fix_str,
                        tags=["dependency", "vulnerability", "npm"],
                    ))
                return findings
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
            return []
        return []

