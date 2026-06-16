"""
Adapter: Go (go.mod / go.sum)
"""
from __future__ import annotations
import csv
import io
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from .base_adapter import BaseAdapter
from ..plugins.base_plugin import Finding, Severity


class GoAdapter(BaseAdapter):
    name = "go"
    project_audit_tool_name = "govulncheck"
    license_tool_name = "go-licenses"
    IGNORE_DIRS = {"vendor"}

    ENV_ACCESS_PATTERNS = [
        (r"os\.Getenv\s*\(", "Go os.Getenv()"),
        (r"os\.LookupEnv\s*\(", "Go os.LookupEnv()"),
        (r"os\.Environ\s*\(", "Go os.Environ()"),
    ]

    REQUIRED_TOOLS = {
        "audit": ("govulncheck", "go install golang.org/x/vuln/cmd/govulncheck@latest"),
        "license": ("go-licenses", "go install github.com/google/go-licenses@latest"),
    }

    def detect(self) -> bool:
        return (self.root / "go.mod").exists()

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {"go": {}},
            "dependencies": {},
            "project_name": self.root.name,
            "project_version": "",
            "framework": "",
        }

        go_mod = self.root / "go.mod"
        if not go_mod.exists():
            return result

        module, packages = self._parse_go_mod(go_mod)
        if module:
            result["project_name"] = module.rsplit("/", 1)[-1]
        result["packages"]["go"] = packages
        result["dependencies"] = {
            name: {"version": ver, "license": "UNKNOWN"} for name, ver in packages.items()
        }

        frameworks = {
            "gin-gonic/gin": "Gin", "labstack/echo": "Echo", "gofiber/fiber": "Fiber",
            "beego/beego": "Beego", "astaxie/beego": "Beego", "gorilla/mux": "Gorilla Mux",
            "go-chi/chi": "Chi", "gobuffalo": "Buffalo", "revel/revel": "Revel",
        }
        for key, label in frameworks.items():
            match = next((p for p in packages if key in p.lower()), None)
            if match:
                result["framework"] = f"{label} {self._clean_version(packages[match])}".strip()
                break

        return result

    @staticmethod
    def _parse_go_mod(path: Path) -> tuple[str, Dict[str, str]]:
        """Parse go.mod: return (module_path, {require_path: version})."""
        module = ""
        packages: Dict[str, str] = {}
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return module, packages

        in_require_block = False
        require_re = re.compile(r"^\s*([^\s]+/[^\s]+)\s+(v[0-9][^\s]*)")
        for raw in lines:
            line = raw.split("//", 1)[0].strip()  # drop `// indirect` comments
            if not line:
                continue
            if line.startswith("module "):
                module = line[len("module "):].strip()
                continue
            if line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block and line == ")":
                in_require_block = False
                continue
            target = line
            if line.startswith("require "):
                target = line[len("require "):].strip()
            if in_require_block or line.startswith("require "):
                m = require_re.match(target)
                if m:
                    packages[m.group(1)] = m.group(2)
        return module, packages

    def check_licenses_with_tool(self, config: Dict) -> List[Finding]:
        """Resolve dependency licenses with `go-licenses csv ./...`.

        Output is CSV: `package,license_url,license_type`. Requires the Go toolchain
        and `go-licenses` on PATH; degrades to a LOW finding otherwise.
        """
        try:
            proc = subprocess.run(
                ["go-licenses", "csv", "./..."],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, cwd=str(self.root)
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return [self._tool_unavailable_finding(
                "go-licenses",
                "go install github.com/google/go-licenses@latest",
                str(e),
            )]

        if not (proc.stdout or "").strip():
            return []

        pairs = []
        for row in csv.reader(io.StringIO(proc.stdout)):
            # rows: [package, license_url, license_type]
            if len(row) >= 3 and row[0].strip():
                pairs.append((row[0].strip(), row[2].strip() or "UNKNOWN"))
        return self._evaluate_licenses(pairs, config)

    def audit_dependencies(self) -> List[Finding]:
        """Run govulncheck (JSON) if available; otherwise OSV in dependency_checker covers Go."""
        try:
            result = subprocess.run(
                ["govulncheck", "-json", "./..."],
                capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(self.root), timeout=180
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

        findings: List[Finding] = []
        seen = set()
        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            osv = record.get("osv") or record.get("finding", {}).get("osv")
            if isinstance(osv, dict):
                vid = osv.get("id", "")
                if vid and vid not in seen:
                    seen.add(vid)
                    summary = osv.get("summary") or osv.get("details", "")[:200]
                    findings.append(Finding(
                        plugin=f"dependency_checker:{self.project_audit_tool_name}",
                        severity=Severity.HIGH,
                        title=f"Go vulnerability: {vid}",
                        description=summary or "Vulnerability reported by govulncheck.",
                        recommendation="Run 'govulncheck ./...' and upgrade affected modules.",
                        tags=["dependency", "vulnerability", "go"],
                    ))
        return findings
