from __future__ import annotations
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, List, Set

from .base_adapter import BaseAdapter
from ..plugins.base_plugin import Finding, Severity
from ..utils.license_utils import _classify_license

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

class PythonAdapter(BaseAdapter):
    name = "python"
    project_audit_tool_name = "pip_audit"
    license_tool_name = "pip-licenses"
    IGNORE_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "venv", ".venv", "env", ".eggs"}

    ENV_ACCESS_PATTERNS = [
        (r"os\.environ\s*\[", "Python os.environ[]"),
        (r"os\.environ\.get\s*\(", "Python os.environ.get()"),
        (r"os\.getenv\s*\(", "Python os.getenv()"),
        (r"from\s+dotenv\s+import", "python-dotenv import"),
        (r"load_dotenv\s*\(", "python-dotenv load_dotenv()"),
    ]

    # 3rd element is the import module name: these run via `python -m <module>`
    # and are detected by import (in the scanner's interpreter), not via PATH.
    REQUIRED_TOOLS = {
        "audit": ("pip-audit", "pip install pip-audit", "pip_audit"),
        "license": ("pip-licenses", "pip install pip-licenses", "piplicenses"),
    }

    def detect(self) -> bool:
        indicators = [
            "requirements.txt", "requirements-dev.txt", "requirements/*.txt",
            "setup.py", "setup.cfg", "pyproject.toml", "Pipfile",
        ]
        for indicator in indicators:
            if "*" in indicator:
                if list(self.root.glob(indicator)):
                    return True
            elif (self.root / indicator).exists():
                return True
        return False

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {},
            "dependencies": {},
            "project_name": self.root.name,
            "project_version": "",
            "framework": "",
        }
        packages = {}
        for req_file in list(self.root.rglob("requirements*.txt"))[:10]:
            packages.update(self._parse_requirements(req_file))
        pipfile = self.root / "Pipfile"
        if pipfile.exists():
            packages.update(self._parse_pipfile(pipfile))
        pyproject = self.root / "pyproject.toml"
        if pyproject.exists():
            meta = self._parse_pyproject(pyproject)
            packages.update(meta.get("packages", {}))
            result["project_name"] = meta.get("name", result["project_name"])
            result["project_version"] = meta.get("version", "")
        result["packages"]["python"] = packages
        framework_map = {
            "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
            "tornado": "Tornado", "aiohttp": "aiohttp", "starlette": "Starlette",
        }
        found = False
        for pkg in packages:
            for key, label in framework_map.items():
                if key in pkg.lower():
                    result["framework"] = f"{label} {self._clean_version(packages.get(pkg, ''))}".strip()
                    found = True
                    break
            if found:
                break
        result["dependencies"] = self._collect_licenses(packages)
        return result

    @staticmethod
    def _parse_requirements(path: Path) -> Dict[str, str]:
        packages = {}
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-r", "-c", "--")):
                continue
            match = re.match(r"([A-Za-z0-9_\-]+)(?:\[.*?\])?\s*(?:[=<>!~]+\s*([^\s;#,]+))?", line)
            if match:
                packages[match.group(1)] = match.group(2) or ""
        return packages

    @staticmethod
    def _parse_pipfile(path: Path) -> Dict[str, str]:
        packages = {}
        in_packages = False
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped in ("[packages]", "[dev-packages]"):
                in_packages = True
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_packages = False
                continue
            if in_packages and "=" in stripped:
                parts = stripped.split("=", 1)
                name = parts[0].strip().strip('"').strip("'")
                version = parts[1].strip().strip('"').strip("'").strip("{").strip("}")
                if name:
                    packages[name] = version
        return packages

    def _parse_pyproject(self, path: Path) -> dict:
        result = {"packages": {}, "name": "", "version": ""}
        if tomllib is None: return result
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            return result
        poetry = data.get("tool", {}).get("poetry", {})
        if poetry:
            result["name"] = poetry.get("name", "")
            result["version"] = poetry.get("version", "")
            deps = poetry.get("dependencies", {})
            dev_deps = poetry.get("dev-dependencies", {})
            for name, ver in {**deps, **dev_deps}.items():
                if name.lower() == "python": continue
                if isinstance(ver, dict):
                    ver = ver.get("version", "*")
                result["packages"][name] = str(ver)
        project = data.get("project", {})
        if project:
            result["name"] = result["name"] or project.get("name", "")
            result["version"] = result["version"] or project.get("version", "")
            for dep in project.get("dependencies", []):
                match = re.match(r"([A-Za-z0-9_\-]+)(?:\[.*?\])?\s*(?:[=<>!~]+\s*([^\s;#,]+))?", dep)
                if match:
                    result["packages"][match.group(1)] = match.group(2) or "*"
        return result

    def _collect_licenses(self, packages: dict) -> dict:
        dep_info = {name: {"version": ver, "license": "UNKNOWN"} for name, ver in packages.items()}
        try:
            result = subprocess.run(
                [sys.executable, "-m", "piplicenses", "--format=json", "--with-license-file",
                 "--ignore-packages", "pip", "setuptools", "wheel"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, cwd=self.root
            )
            if result.returncode == 0 and result.stdout:
                licenses_data = json.loads(result.stdout)
                for item in licenses_data:
                    name = item.get("Name", "")
                    if name in dep_info:
                        dep_info[name]["license"] = item.get("License", "UNKNOWN")
                return dep_info
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return dep_info
        
    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        findings = []
        try:
            result = subprocess.run(
                [sys.executable, "-m", "piplicenses", "--format=json"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, cwd=self.root
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return [Finding(
                plugin="license_checker",
                severity=Severity.LOW,
                title="Python pip-licenses tool failed",
                description=str(e),
                recommendation="Install pip-licenses into the scanner's Python: "
                               f"{sys.executable} -m pip install pip-licenses",
                tags=["license", "tool-failure", "python"],
            )]

        if result.returncode != 0 or not result.stdout:
            return []
            
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        if not data:
            return [Finding(
                plugin="license_checker",
                severity=Severity.LOW,
                title="Python dependencies not found",
                description="The pip-licenses tool did not find any installed packages. Dependencies may not be installed in the current environment.",
                recommendation="Run 'pip install -r requirements.txt' in the correct environment before scanning.",
                tags=["license", "tool-failure", "python"],
            )]

        denied = set(c.upper() for c in config.get("deny", []))
        allowed_class = set(config.get("allow_classifications", []))
        
        for item in data:
            pkg_name = item.get("Name")
            license_str = item.get("License", "UNKNOWN")

            # pip-licenses returns the raw `License:` metadata field. Packages that
            # declare `license = {file = "LICENSE"}` put the ENTIRE license text
            # there, not an SPDX id/expression. A multi-line / long blob can't be
            # classified reliably — naive substring matching both mis-fires (full MIT
            # text incidentally contains weak-copyleft keywords) and would tokenize
            # "Copyright (c) ..." into junk like "c" — so treat it as undetermined
            # rather than emit a false finding.
            if "\n" in license_str or len(license_str) > 200:
                continue

            licenses = [l.strip() for l in re.split(r'OR|AND|[()/]', license_str) if l.strip()]
            if not licenses:
                licenses = [license_str]

            for lic in licenses:
                if lic.upper() in denied:
                    findings.append(Finding(
                        plugin="license_checker",
                        severity=Severity.CRITICAL,
                        title=f"Denied license: {pkg_name} ({lic})",
                        description=f"Package '{pkg_name}' uses a denied license '{lic}'.",
                        recommendation=f"Remove or replace the dependency '{pkg_name}' to comply with the license policy.",
                        tags=["license", "dependency", "python"],
                    ))
                    break

                classification = _classify_license(lic)
                # Undetermined licenses can't be judged — usually it just means the
                # package's metadata has no recognizable license id, NOT a real policy
                # violation. Skip them here (consistent with _check_licenses_by_content)
                # instead of raising a false HIGH.
                if classification in ("unknown", "no-license"):
                    continue
                if classification not in allowed_class:
                    findings.append(Finding(
                        plugin="license_checker",
                        severity=Severity.HIGH,
                        title=f"Non-compliant license: {pkg_name} ({lic}) - {classification}",
                        description=f"Package '{pkg_name}' uses license '{lic}' which is classified as '{classification}'.",
                        recommendation="Review your project's license policy and consider replacing this dependency.",
                        tags=["license", "dependency", "python"],
                    ))
                    break
        return findings

    def audit_dependencies(self) -> List[Finding]:
        """Run pip-audit and return vulnerabilities."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--format=json", "--progress-spinner=off"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=self.root, timeout=120
            )
            if result.stdout:
                data = json.loads(result.stdout)
                vulns = data.get("dependencies", [])
                findings = []
                for item in vulns:
                    for vuln in item.get("vulns", []):
                        findings.append(Finding(
                            plugin=f"dependency_checker:{self.project_audit_tool_name}",
                            severity=Severity.HIGH,
                            title=f"Python vulnerability: {item['name']}@{item['version']}",
                            description=(
                                f"{vuln.get('id', 'Unknown')}: {vuln.get('description', 'No description')[:200]}"
                            ),
                            recommendation=(
                                f"Upgrade to a fixed version: {vuln.get('fix_versions', ['N/A'])}. "
                                "See: https://osv.dev"
                            ),
                            tags=["dependency", "vulnerability", "python"],
                        ))
                return findings
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
            return []
        return []
