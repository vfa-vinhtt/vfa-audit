"""
Adapter: PHP (Composer)
"""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from .base_adapter import BaseAdapter
from ..plugins.base_plugin import Finding, Severity


class PHPAdapter(BaseAdapter):
    name = "php"
    license_tool_name = "composer"
    project_audit_tool_name = "composer_audit"
    IGNORE_DIRS = {"vendor"}

    ENV_ACCESS_PATTERNS = [
        (r"\$_ENV\s*\[", "PHP $_ENV[]"),
        (r"\$_SERVER\s*\[", "PHP $_SERVER[]"),
        (r"\bgetenv\s*\(", "PHP getenv()"),
        (r"\benv\s*\(\s*['\"]", "Laravel env()"),
    ]

    REQUIRED_TOOLS = {
        "audit": ("composer", "https://getcomposer.org/ (composer audit)"),
        "license": ("composer", "https://getcomposer.org/ (composer licenses)"),
    }

    def detect(self) -> bool:
        return (self.root / "composer.json").exists()

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {},
            "dependencies": {},
            "project_name": self.root.name,
            "project_version": "",
            "framework": "",
        }

        composer_json = self.root / "composer.json"
        try:
            data = json.loads(composer_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return result

        result["project_name"] = data.get("name", self.root.name).split("/")[-1]
        result["project_version"] = data.get("version", "")

        packages = {}
        packages.update(data.get("require", {}))
        packages.update(data.get("require-dev", {}))
        # Remove PHP runtime requirement
        packages.pop("php", None)
        packages.pop("ext-json", None)

        # Nest packages under the ecosystem key expected by dependency_checker
        # ({ecosystem: {pkg: ver}}), matching the python/node adapters.
        result["packages"] = {"php": packages}

        # Detect framework (+ version)
        php_frameworks = [
            ("laravel/framework", "Laravel"), ("symfony/framework-bundle", "Symfony"),
            ("slim/slim", "Slim"), ("yiisoft/yii2", "Yii2"),
            ("codeigniter4/framework", "CodeIgniter"),
        ]
        for pkg, label in php_frameworks:
            if pkg in packages:
                result["framework"] = f"{label} {self._clean_version(packages[pkg])}".strip()
                break

        # Read license info from composer.lock if available
        result["dependencies"] = self._parse_lock(packages)

        return result

    def _parse_lock(self, packages: dict) -> dict:
        dep_info = {name: {"version": ver, "license": "UNKNOWN"} for name, ver in packages.items()}

        lock_file = self.root / "composer.lock"
        if not lock_file.exists():
            return dep_info

        try:
            lock = json.loads(lock_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return dep_info

        all_pkgs = lock.get("packages", []) + lock.get("packages-dev", [])
        for pkg in all_pkgs:
            name = pkg.get("name", "")
            if name in dep_info:
                lic = pkg.get("license", [])
                if isinstance(lic, list):
                    lic = ", ".join(lic)
                dep_info[name]["license"] = lic or "UNKNOWN"
                dep_info[name]["version"] = pkg.get("version", dep_info[name]["version"])

        return dep_info

    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        """Resolve licenses with `composer licenses --format=json`.

        composer's built-in licenses command is the canonical, parseable source
        (composer-license-checker is an allow/deny enforcement wrapper over the same
        data without per-package JSON). Degrades to a LOW finding when composer is
        unavailable.
        """
        try:
            proc = subprocess.run(
                ["composer", "licenses", "--format=json", "--no-interaction"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, cwd=str(self.root)
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return [self._tool_unavailable_finding(
                "composer", "https://getcomposer.org/ (uses `composer licenses --format=json`)", str(e),
            )]

        if not (proc.stdout or "").strip():
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        pairs = []
        for name, info in (data.get("dependencies") or {}).items():
            lic = info.get("license", [])
            lic = ", ".join(lic) if isinstance(lic, list) else str(lic)
            pairs.append((name, lic or "UNKNOWN"))
        return self._evaluate_licenses(pairs, config)

    def audit_dependencies(self) -> List[Finding]:
        """Run `composer audit` (Composer 2.4+) and report advisories as findings.

        Best-effort: requires composer and an installed/locked project. Returns []
        when unavailable. OSV (Packagist) covers the same packages otherwise.
        """
        try:
            proc = subprocess.run(
                ["composer", "audit", "--format=json", "--no-interaction"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(self.root), timeout=120
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

        if not proc.stdout:
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM, "low": Severity.LOW,
        }
        findings: List[Finding] = []
        advisories = data.get("advisories", {})
        for pkg, advs in advisories.items():
            for adv in (advs if isinstance(advs, list) else []):
                sev = sev_map.get(str(adv.get("severity", "")).lower(), Severity.MEDIUM)
                ident = adv.get("cve") or adv.get("advisoryId") or ""
                link = adv.get("link") or "https://github.com/advisories"
                findings.append(Finding(
                    plugin="dependency_checker:composer_audit",
                    severity=sev,
                    title=f"PHP vulnerability: {pkg} {ident}".strip(),
                    description=(adv.get("title") or "Security advisory reported by composer audit.")[:200],
                    recommendation=f"Update '{pkg}' to a patched version. Advisory: {link}",
                    tags=["dependency", "vulnerability", "php"],
                ))
        return findings
