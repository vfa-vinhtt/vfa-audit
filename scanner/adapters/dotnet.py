"""
Adapter: .NET (C# / .csproj / packages.config / NuGet)
"""
from __future__ import annotations
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List

from .base_adapter import BaseAdapter
from ..plugins.base_plugin import Finding, Severity

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None  # type: ignore


class DotNetAdapter(BaseAdapter):
    name = "dotnet"
    license_tool_name = "dotnet-project-licenses"
    project_audit_tool_name = "dotnet_audit"
    IGNORE_DIRS = {"bin", "obj"}

    ENV_ACCESS_PATTERNS = [
        (r"Environment\.GetEnvironmentVariable\s*\(", ".NET Environment.GetEnvironmentVariable()"),
        (r"\bDotNetEnv\b", ".NET DotNetEnv"),
        (r"_?[Cc]onfiguration\s*\[\s*['\"]", ".NET IConfiguration indexer"),
    ]

    REQUIRED_TOOLS = {
        "audit": ("dotnet", "https://dotnet.microsoft.com/download"),
        "license": ("dotnet-project-licenses", "dotnet tool install --global dotnet-project-licenses"),
    }

    def detect(self) -> bool:
        return bool(
            list(self.root.rglob("*.csproj"))
            or list(self.root.rglob("*.fsproj"))
            or list(self.root.rglob("*.vbproj"))
            or (self.root / "packages.config").exists()
        )

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {},
            "dependencies": {},
            "project_name": self.root.name,
            "project_version": "",
            "framework": "",
        }

        # Parse all .csproj files
        csproj_files = list(self.root.rglob("*.csproj"))[:20]
        for csproj in csproj_files:
            self._parse_csproj(csproj, result)

        # Parse packages.config (legacy NuGet)
        pkg_config = self.root / "packages.config"
        if pkg_config.exists():
            self._parse_packages_config(pkg_config, result)

        # Nest packages under the ecosystem key expected by dependency_checker
        # ({ecosystem: {pkg: ver}}), matching the python/node adapters.
        # (Vulnerability auditing happens in audit_dependencies(), not here.)
        result["packages"] = {"dotnet": result["packages"]}
        return result

    def _parse_csproj(self, path: Path, result: dict) -> None:
        if ET is None:
            return
        try:
            tree = ET.parse(str(path))
            root_el = tree.getroot()

            # PackageReference (SDK-style)
            for ref in root_el.iter("PackageReference"):
                name = ref.get("Include", "") or ref.get("include", "")
                version = (ref.get("Version", "") or ref.get("version", "")
                           or (ref.find("Version").text if ref.find("Version") is not None else ""))
                if name:
                    result["packages"][name] = version or "UNKNOWN"
                    result["dependencies"][name] = {"version": version or "UNKNOWN", "license": "UNKNOWN"}

            # Detect framework target
            for prop in root_el.iter("TargetFramework"):
                tf = prop.text or ""
                result["project_version"] = tf
                if "net8" in tf or "net7" in tf or "net6" in tf:
                    result["framework"] = f".NET {tf}"
                elif "netcoreapp" in tf:
                    result["framework"] = ".NET Core"
                elif "netstandard" in tf:
                    result["framework"] = ".NET Standard"
                elif "net4" in tf or "net3" in tf:
                    result["framework"] = ".NET Framework"

            # Project name from AssemblyName or file
            for prop in root_el.iter("AssemblyName"):
                if prop.text:
                    result["project_name"] = prop.text.strip()
                    break

        except Exception:
            pass

    def _parse_packages_config(self, path: Path, result: dict) -> None:
        if ET is None:
            return
        try:
            tree = ET.parse(str(path))
            for pkg in tree.getroot().iter("package"):
                name = pkg.get("id", "")
                version = pkg.get("version", "UNKNOWN")
                if name:
                    result["packages"][name] = version
                    result["dependencies"][name] = {"version": version, "license": "UNKNOWN"}
        except Exception:
            pass

    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        """Resolve licenses with `dotnet-project-licenses --json`.

        The tool writes a `licenses.json` array of objects with PackageName /
        PackageVersion / LicenseType. We direct it to a temp dir so the scanned
        project is not modified. Degrades to a LOW finding when unavailable.
        """
        out_dir = Path(tempfile.mkdtemp(prefix="dotnet_lic_"))
        try:
            proc = subprocess.run(
                ["dotnet-project-licenses", "--input", str(self.root),
                 "--json", "--output-directory", str(out_dir)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, cwd=str(self.root)
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            shutil.rmtree(out_dir, ignore_errors=True)
            return [self._tool_unavailable_finding(
                "dotnet-project-licenses",
                "dotnet tool install --global dotnet-project-licenses",
                str(e),
            )]

        pairs = []
        try:
            report = out_dir / "licenses.json"
            if report.exists():
                data = json.loads(report.read_text(encoding="utf-8"))
            elif (proc.stdout or "").strip().startswith("["):
                data = json.loads(proc.stdout)
            else:
                data = []
            for item in (data if isinstance(data, list) else []):
                name = item.get("PackageName") or item.get("packageName") or item.get("name")
                lic = (item.get("LicenseType") or item.get("License")
                       or item.get("license") or "UNKNOWN")
                if name:
                    pairs.append((name, lic if isinstance(lic, str) else "UNKNOWN"))
        except (json.JSONDecodeError, OSError):
            pairs = []
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

        return self._evaluate_licenses(pairs, config)

    def audit_dependencies(self) -> List[Finding]:
        """Run `dotnet list package --vulnerable` and report advisories as findings.

        Best-effort: requires the .NET SDK and restored packages. Returns [] when the
        tool is unavailable. OSV (NuGet) covers the same packages when the SDK is absent.
        """
        try:
            proc = subprocess.run(
                ["dotnet", "list", "package", "--vulnerable", "--include-transitive"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(self.root), timeout=120
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

        output = proc.stdout or ""
        sev_map = {
            "critical": Severity.CRITICAL, "high": Severity.HIGH,
            "moderate": Severity.MEDIUM, "medium": Severity.MEDIUM, "low": Severity.LOW,
        }
        # Line form (top-level and transitive): "> Package [Requested] Resolved Severity URL"
        pattern = re.compile(
            r">\s+(\S+)\s+(?:\S+\s+)*?(\S+)\s+(Critical|High|Moderate|Medium|Low)\s+(https?://\S+)",
            re.IGNORECASE,
        )
        findings: List[Finding] = []
        seen = set()
        for match in pattern.finditer(output):
            pkg, ver, sev, url = match.groups()
            key = (pkg, url)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                plugin="dependency_checker:dotnet_audit",
                severity=sev_map.get(sev.lower(), Severity.MEDIUM),
                title=f".NET vulnerability: {pkg}@{ver}",
                description=f"Package '{pkg}' {ver} has a {sev.lower()} severity advisory.",
                recommendation=f"Update '{pkg}' to a fixed version. Advisory: {url}",
                tags=["dependency", "vulnerability", "dotnet"],
            ))
        return findings
