"""
Adapter: Java (Maven pom.xml / Gradle build.gradle)
"""
from __future__ import annotations
import re
import subprocess
from pathlib import Path
from typing import Dict, Any

from .base_adapter import BaseAdapter

try:
    import xml.etree.ElementTree as ET
except ImportError:
    ET = None  # type: ignore


class JavaAdapter(BaseAdapter):
    name = "java"
    IGNORE_DIRS = {"target", ".gradle"}

    ENV_ACCESS_PATTERNS = [
        (r"System\.getenv\s*\(", "Java System.getenv()"),
        (r"@Value\s*\(\s*['\"]\$\{", "Spring @Value(\"${...}\")"),
        (r"System\.getProperty\s*\(", "Java System.getProperty()"),
    ]

    def detect(self) -> bool:
        return any([
            (self.root / "pom.xml").exists(),
            (self.root / "build.gradle").exists(),
            (self.root / "build.gradle.kts").exists(),
            bool(list(self.root.rglob("build.gradle"))),
            bool(list(self.root.rglob("build.gradle.kts"))),
        ])

    def collect(self) -> Dict[str, Any]:
        result = {
            "packages": {},
            "dependencies": {},
            "project_name": self.root.name,
            "project_version": "",
            "framework": "",
        }

        if (self.root / "pom.xml").exists():
            self._parse_maven(result)
        else:
            # Gradle (incl. Android & Kotlin DSL). Scan the root build file plus
            # module build files (e.g. Android's app/build.gradle) so multi-module
            # dependencies are captured, not just the root project's.
            gradle_files = (
                list(self.root.rglob("build.gradle"))
                + list(self.root.rglob("build.gradle.kts"))
            )
            for gradle_file in gradle_files[:25]:
                self._parse_gradle(gradle_file, result)

        # Nest packages under the ecosystem key expected by dependency_checker
        # ({ecosystem: {pkg: ver}}), matching the python/node adapters.
        result["packages"] = {"java": result["packages"]}
        return result

    def _parse_maven(self, result: dict) -> None:
        if ET is None:
            return
        try:
            tree = ET.parse(str(self.root / "pom.xml"))
            root_el = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}

            # Handle namespaced and non-namespaced
            def find(el, path):
                found = el.find(path, ns)
                if found is None:
                    found = el.find(path.replace("m:", ""))
                return found

            name_el = find(root_el, "m:name")
            if name_el is None:
                name_el = find(root_el, "m:artifactId")
            if name_el is not None and name_el.text:
                result["project_name"] = name_el.text.strip()

            version_el = find(root_el, "m:version")
            if version_el is not None and version_el.text:
                result["project_version"] = version_el.text.strip()

            # Collect dependencies
            deps_el = find(root_el, "m:dependencies")
            if deps_el is None:
                return

            dep_elements = deps_el.findall("m:dependency", ns)
            if not dep_elements:
                dep_elements = deps_el.findall("dependency")

            for dep in dep_elements:
                # ElementTree leaf elements are falsy (no children), so `elem or fallback`
                # silently discards a real match — always compare with `is None`.
                group = find(dep, "m:groupId")
                artifact = find(dep, "m:artifactId")
                version = find(dep, "m:version")
                if artifact is not None and artifact.text:
                    group_text = group.text if (group is not None and group.text) else ""
                    name = f"{group_text}:{artifact.text}"
                    ver = version.text.strip() if (version is not None and version.text) else "UNKNOWN"
                    # Resolve property placeholders
                    ver = re.sub(r"\$\{[^}]+\}", "PROPERTY", ver)
                    result["packages"][name] = ver
                    result["dependencies"][name] = {"version": ver, "license": "UNKNOWN"}

            # Detect framework
            pkg_names = " ".join(result["packages"].keys()).lower()
            if "spring-boot" in pkg_names:
                result["framework"] = "Spring Boot"
            elif "spring" in pkg_names:
                result["framework"] = "Spring"
            elif "quarkus" in pkg_names:
                result["framework"] = "Quarkus"
            elif "micronaut" in pkg_names:
                result["framework"] = "Micronaut"
            elif "jakarta" in pkg_names or "javax.faces" in pkg_names:
                result["framework"] = "Jakarta EE"

        except Exception:
            pass

    def _parse_gradle(self, gradle_file: Path, result: dict) -> None:
        try:
            content = gradle_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return

        # Extract group:artifact:version patterns. Covers Groovy and Kotlin DSL
        # configurations (implementation/api/kapt/androidTestImplementation/...).
        # Handles Groovy (implementation 'x:y:1') and Kotlin DSL (implementation("x:y:1")):
        # optional '(', optional whitespace, then the quoted "group:artifact:version".
        dep_pattern = re.compile(
            r"""(?:implementation|api|compile|testImplementation|androidTestImplementation"""
            r"""|debugImplementation|releaseImplementation|kapt|ksp|runtimeOnly|annotationProcessor)"""
            r"""\s*\(?\s*['"]([A-Za-z0-9.\-]+:[A-Za-z0-9.\-]+):([A-Za-z0-9.\-${}]+)['"]\)?""",
            re.MULTILINE
        )
        for match in dep_pattern.finditer(content):
            name = match.group(1)
            version = match.group(2)
            result["packages"][name] = version
            result["dependencies"][name] = {"version": version, "license": "UNKNOWN"}

        # Extract project name (don't overwrite a name already found)
        name_match = re.search(r"""rootProject\.name\s*[=:]\s*['"]([^'"]+)['"]""", content)
        if name_match and not result.get("project_version") and result["project_name"] == self.root.name:
            result["project_name"] = name_match.group(1)

        # Detect framework / platform (don't overwrite one already detected)
        if not result["framework"]:
            pkg_str = " ".join(result["packages"].keys()).lower()
            if "com.android" in pkg_str or "androidx." in pkg_str or "android" in content.lower()[:2000]:
                result["framework"] = "Android"
            if "spring-boot" in pkg_str or "org.springframework.boot" in pkg_str:
                result["framework"] = "Spring Boot"
            elif "quarkus" in pkg_str:
                result["framework"] = "Quarkus"

    def _try_dependency_check(self, root: Path) -> dict:
        """Run OWASP Dependency Check if available."""
        vulnerabilities = {}
        try:
            result = subprocess.run(
                ["dependency-check", "--scan", str(root), "--format", "JSON",
                 "--out", str(root / ".security-scan" / "owasp"), "--prettyPrint"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, cwd=str(root)
            )
            # Parse output if successful
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return vulnerabilities
