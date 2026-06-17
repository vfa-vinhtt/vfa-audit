"""
Plugin: Secret Checker
Detects hardcoded credentials, API keys, passwords, tokens, and other secrets
using regex patterns and Shannon entropy analysis.
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple

from .base_plugin import BasePlugin, Finding, Severity
from ..core.requirements import resolve_command
from ..core.trivy_adapter import run_trivy

# ─────────────────────────────────────────────────────────────────────────────
# Pattern definitions: (name, regex, severity, recommendation)
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS: List[Tuple[str, str, Severity, str]] = [
    # Cloud providers
    ("AWS Access Key ID", r"(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", Severity.CRITICAL,
     "Rotate this AWS key immediately via IAM console and revoke the old one."),
    ("AWS Secret Access Key", r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*['\"]?[0-9a-zA-Z/+]{40}['\"]?", Severity.CRITICAL,
     "Rotate AWS credentials. Never hardcode them — use IAM roles or AWS Secrets Manager."),
    ("AWS MFA Serial", r"arn:aws:iam::\d{12}:mfa/", Severity.MEDIUM,
     "Do not hardcode AWS account IDs or MFA serial numbers."),
    ("GCP API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.CRITICAL,
     "Revoke this GCP API key and restrict future keys by IP/referrer."),
    ("GCP Service Account", r"[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com", Severity.HIGH,
     "Use workload identity or GCP Secret Manager instead of hardcoding service account emails."),
    ("Azure Storage Key", r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", Severity.CRITICAL,
     "Rotate Azure Storage account key and use Managed Identity or Key Vault."),
    ("Azure SAS Token", r"(?i)se=\d{4}-\d{2}-\d{2}&sp=[a-z]+&sv=\d{4}-\d{2}-\d{2}&sr=[a-z]+&sig=[A-Za-z0-9%=]+", Severity.HIGH,
     "Revoke SAS token and generate time-limited tokens only when needed."),

    # Source control tokens
    ("GitHub Personal Access Token", r"ghp_[A-Za-z0-9]{36}", Severity.CRITICAL,
     "Revoke token at github.com/settings/tokens and use fine-grained tokens."),
    ("GitHub OAuth Token", r"gho_[A-Za-z0-9]{36}", Severity.CRITICAL,
     "Revoke GitHub OAuth token immediately."),
    ("GitHub Actions Token", r"ghs_[A-Za-z0-9]{36}", Severity.HIGH,
     "GitHub Actions secrets should use GITHUB_TOKEN scoping."),
    ("GitLab Personal Access Token", r"glpat-[A-Za-z0-9_\-]{20}", Severity.CRITICAL,
     "Revoke this GitLab PAT and restrict future tokens by scope."),

    # Payment processors
    ("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL,
     "Revoke immediately via Stripe dashboard. Use environment variables."),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", Severity.MEDIUM,
     "Publishable keys are less sensitive but should not be hardcoded in server-side code."),
    ("PayPal Client Secret", r"(?i)paypal[_\-\s]?(?:client[_\-\s]?)?secret\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?", Severity.CRITICAL,
     "Rotate PayPal credentials and use environment variables."),
    ("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", Severity.CRITICAL,
     "Revoke Square token at developer.squareup.com."),

    # Communication services
    ("Twilio Account SID", r"AC[a-fA-F0-9]{32}", Severity.HIGH,
     "Rotate Twilio credentials and use environment variables."),
    ("Twilio Auth Token", r"(?i)twilio[_\-\s]?auth[_\-\s]?token\s*[=:]\s*['\"]?[a-fA-F0-9]{32}['\"]?", Severity.CRITICAL,
     "Rotate Twilio auth token via Twilio console."),
    ("Slack Bot Token", r"xoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}", Severity.CRITICAL,
     "Revoke Slack token at api.slack.com/apps."),
    ("Slack User Token", r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{32}", Severity.CRITICAL,
     "Revoke Slack token at api.slack.com/apps."),
    ("SendGrid API Key", r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", Severity.CRITICAL,
     "Revoke key via SendGrid dashboard and use environment variables."),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", Severity.HIGH,
     "Rotate Mailgun API key."),

    # Cryptographic keys
    ("RSA Private Key", r"-----BEGIN\s+(?:RSA\s+)?PRIVATE KEY-----", Severity.CRITICAL,
     "Remove private key from source code. Store in a secrets manager or hardware security module."),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", Severity.CRITICAL,
     "Remove EC private key from source code immediately."),
    ("PGP Private Key Block", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", Severity.CRITICAL,
     "Remove PGP private key from source code immediately."),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", Severity.CRITICAL,
     "Remove SSH private key from source code immediately."),
    ("Certificate", r"-----BEGIN CERTIFICATE-----", Severity.MEDIUM,
     "Public certificates are less sensitive, but verify this is intentional."),

    # Databases
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[^:]+:[^@]+@", Severity.CRITICAL,
     "Use environment variables or a secrets manager for MongoDB credentials."),
    ("PostgreSQL Connection String", r"postgresql?://[^:]+:[^@]+@", Severity.CRITICAL,
     "Never hardcode database credentials. Use connection pooling with env vars."),
    ("MySQL Connection String", r"mysql://[^:]+:[^@]+@", Severity.CRITICAL,
     "Use environment variables for MySQL credentials."),
    ("Redis URL with Password", r"redis://:?[^@\s]+@[^\s]+", Severity.HIGH,
     "Use environment variables for Redis credentials."),
    ("JDBC Connection String", r"jdbc:[a-z]+://[^;]+;(?:user|username)=[^;]+;password=[^;]+", Severity.CRITICAL,
     "Move JDBC credentials to environment variables or a vault."),

    # Generic patterns (lower confidence, high value when matched)
    ("Hardcoded Password", r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*['\"][^\s'\"]{6,}['\"]", Severity.HIGH,
     "Use environment variables or a secrets manager. Never hardcode passwords."),
    ("Hardcoded API Key", r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key)\s*[=:]\s*['\"][^\s'\"]{16,}['\"]", Severity.HIGH,
     "Use environment variables or a secrets manager for API keys."),
    ("Hardcoded Secret", r"(?i)(?:secret|token|auth)[_\-]?(?:key|token|secret)?\s*[=:]\s*['\"][^\s'\"]{16,}['\"]", Severity.HIGH,
     "Use environment variables or a secrets manager."),
    ("Bearer Token", r"Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}", Severity.MEDIUM,
     "Do not hardcode bearer tokens. Fetch them dynamically."),
    ("Basic Auth in URL", r"https?://[A-Za-z0-9_\-]+:[^@\s]+@", Severity.HIGH,
     "Never embed credentials in URLs. Use Authorization headers with env vars."),
    ("JWT Token", r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*", Severity.MEDIUM,
     "Hardcoded JWTs may contain sensitive claims. Use dynamic token generation."),

    # Infrastructure
    ("NPM Auth Token", r"//registry\.npmjs\.org/:_authToken\s*=\s*[^\s]+", Severity.CRITICAL,
     "Revoke npm token and use CI environment variables."),
    ("Docker Registry Password", r"(?i)(?:docker|registry)[_\-]?password\s*[=:]\s*['\"][^\s'\"]+['\"]", Severity.HIGH,
     "Use Docker credential helpers or CI secrets."),
    ("Kubernetes Secret", r"(?i)kubectl\s+create\s+secret.*--from-literal.*[=:][^\s]{8,}", Severity.HIGH,
     "Use Kubernetes Secrets or a vault integration."),
    ("SSH Password", r"(?i)StrictHostKeyChecking\s*no.*sshpass", Severity.HIGH,
     "Never disable SSH host key checking or use password-based SSH in code."),
]

# File extensions to skip for secret scanning (binary/generated)
SKIP_EXTENSIONS = {
    ".lock", ".sum", ".mod",
    ".min.js", ".min.css",  # Minified files
}

# Files commonly containing placeholder/example secrets (lower severity context)
EXAMPLE_FILE_PATTERNS = {
    "example", "sample", "template", "fixture", "mock", "fake",
    "test", "spec", "stub", ".example", ".sample",
}

# Entropy thresholds for high-entropy string detection
ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LENGTH = 20


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())



class SecretChecker(BasePlugin):
    name = "secret_checker"
    description = "Detects hardcoded secrets, passwords, and API keys"

    # Source extensions to scan
    SOURCE_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".php",
        ".go", ".rb", ".rs", ".cpp", ".c", ".h", ".swift", ".kt",
        ".yaml", ".yml", ".json", ".xml", ".properties", ".toml",
        ".ini", ".cfg", ".conf", ".config", ".env", ".sh", ".bash",
        ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".tf", ".tfvars",
        ".dockerfile", ".gradle", ".gradle.kts",
        "",  # files without extension (e.g. Makefile, Dockerfile)
    }

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        tool_config = self.config.get("tool_config", {})

        # Run EVERY enabled tool and merge results (each is reported under its own
        # sub-plugin, e.g. secret_checker:gitleaks). The preflight check requires any
        # enabled external tool, so a missing one is caught before scanning.
        dispatch = {
            "python_regex": self._scan_with_python_regex,
            "gitleaks": self._scan_with_gitleaks,
            "trufflehog": self._scan_with_trufflehog,
            "trivy": self._scan_with_trivy_secrets,
        }
        enabled_tools = [t for t, s in tool_config.items() if s.get("enabled") and t in dispatch]

        if not enabled_tools:
            self.name = "secret_checker"
            self.add_finding(
                severity=Severity.INFO,
                title="No secret scanning tool enabled",
                description="No secret scanning tool was enabled in the configuration.",
                recommendation="Enable one of 'python_regex', 'gitleaks', or 'trufflehog' in your config.yaml.",
                tags=["configuration"],
            )
            return self.findings

        all_findings: List[Finding] = []
        for tool in enabled_tools:
            self.name = f"secret_checker:{tool}"
            self.findings = []
            tool_findings = dispatch[tool](root, files, context)
            if not tool_findings:
                # The tool ran but flagged nothing. Emit an INFO so the report still
                # shows the tool's subgroup and confirms it actually executed (otherwise
                # a clean external scan like gitleaks would be invisible).
                self.findings = []
                self.add_finding(
                    severity=Severity.INFO,
                    title=f"{tool} scan completed - no secrets found",
                    description=f"The '{tool}' secret scanner ran successfully and reported no secrets.",
                    recommendation="No action needed; the scanner executed and found nothing.",
                    tags=["secret", tool, "scan-summary"],
                )
                tool_findings = self.findings
            all_findings.extend(tool_findings)

        self.name = "secret_checker"
        self.findings = all_findings
        return all_findings

    def _scan_with_python_regex(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        compile_patterns = self._compile_patterns()
        seen = set()

        for f in files:
            if f.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if f.suffix.lower() not in self.SOURCE_EXTENSIONS and f.suffix != "":
                continue

            is_example = any(
                marker in f.name.lower() or marker in str(f.parent).lower()
                for marker in EXAMPLE_FILE_PATTERNS
            )

            lines = self._read_lines(f)
            rel = str(f.relative_to(root))

            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") and not stripped.startswith("#!"):
                    if stripped.startswith("#") and stripped.startswith("#!"):
                        pass
                    elif stripped.startswith("#"):
                        continue

                for pattern_name, regex, severity, rec in compile_patterns:
                    match = regex.search(line)
                    if not match:
                        continue

                    key = (rel, line_num, pattern_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    actual_severity = (
                        Severity.LOW if is_example and severity in (Severity.HIGH, Severity.MEDIUM)
                        else severity
                    )
                    evidence = self._mask_secret(line, match)
                    self.add_finding(
                        severity=actual_severity,
                        title=f"Hardcoded secret: {pattern_name}",
                        description=(
                            f"Potential {pattern_name} found in '{rel}' at line {line_num}."
                            + (" (example/test file — verify this is a placeholder)" if is_example else "")
                        ),
                        recommendation=rec,
                        file=rel,
                        line=line_num,
                        evidence=evidence,
                        tags=["secret", "hardcoded", pattern_name.lower().replace(" ", "_")],
                    )
            self._check_high_entropy(lines, rel, f, is_example, seen)
        return self.findings

    def _scan_with_gitleaks(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        """Runs gitleaks and parses its JSON report.

        gitleaks exit codes: 0 = no leaks, 1 = leaks found, >1 = execution error. We
        must NOT use check=True (exit 1 is a successful scan WITH findings). The report
        is written to a temp file so the scanned tree isn't polluted.
        """
        self.findings = []
        report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
        os.close(report_fd)
        # gitleaks excludes paths via a TOML config that keeps the default ruleset and
        # allowlists the ignored directories.
        excludes = self._exclude_dir_regexes(context)
        config_text = ""
        if excludes:
            paths = ",\n  ".join(f"'''{rx}'''" for rx in excludes)
            config_text = (
                "[extend]\nuseDefault = true\n\n"
                "[[allowlists]]\n"
                'description = "security-scanner directory excludes"\n'
                f"paths = [\n  {paths}\n]\n"
            )
        config_path = self._write_temp(config_text, "gitleaks-cfg-", ".toml")
        is_git_repo = bool(context.get("is_git_repo"))
        try:
            command = [
                resolve_command("gitleaks") or "gitleaks",
                "detect",
                "--source", str(root),
                "--report-format", "json",
                "--report-path", report_path,
            ]
            if not is_git_repo:
                command.append("--no-git")
            if config_path:
                command += ["--config", config_path]
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)

            if result.returncode > 1:  # >1 is a real execution error
                self.add_finding(
                    severity=Severity.WARNING,
                    title="Gitleaks scan failed",
                    description=f"Gitleaks exited {result.returncode}: {(result.stderr or '').strip()[:300]}",
                    recommendation="Ensure gitleaks is installed and functioning correctly.",
                    tags=["tool-failure", "gitleaks"],
                )
                return self.findings

            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, "r", encoding="utf-8") as f:
                    leaks = json.load(f)
                for leak in leaks:
                    rule = leak.get("RuleID", "secret")
                    self.add_finding(
                        severity=Severity.HIGH,
                        title=f"Gitleaks: {leak.get('Description') or rule}",
                        description=f"Secret detected in {leak.get('File')} at line {leak.get('StartLine')}.",
                        recommendation=f"Rule '{rule}'. Rotate the secret and remove it from git history.",
                        file=self._rel_path(leak.get("File"), root),
                        line=leak.get("StartLine"),
                        evidence=self._mask_value(leak.get("Secret") or leak.get("Match") or ""),
                        tags=["secret", "gitleaks", rule],
                    )
        except FileNotFoundError:
            return [self._tool_not_found_finding("gitleaks")]
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            self.add_finding(
                severity=Severity.WARNING,
                title="Gitleaks scan failed",
                description=f"Gitleaks execution failed: {e}",
                recommendation="Ensure gitleaks is installed and functioning correctly.",
                tags=["tool-failure", "gitleaks"],
            )
        finally:
            for _p in (report_path, config_path):
                if _p:
                    try:
                        os.unlink(_p)
                    except OSError:
                        pass
        return self.findings

    @staticmethod
    def _rel_path(raw, root) -> str:
        """Normalize a tool-reported path to a root-relative, forward-slash form.

        gitleaks/trufflehog report absolute (or differently-separated) paths while the
        built-in scanner uses paths relative to root. Without this, the same file looks
        different to each tool and cross-tool dedup in the report never matches.
        """
        if not raw:
            return raw
        try:
            p = Path(str(raw))
            if p.is_absolute():
                p = p.relative_to(Path(root))
            return p.as_posix()
        except (ValueError, OSError):
            return str(raw).replace("\\", "/")

    @staticmethod
    def _mask_value(secret: str) -> str:
        """Partially mask a raw secret value for safe display in the report."""
        secret = (secret or "").strip()
        if len(secret) <= 6:
            return "*" * len(secret)
        return secret[:3] + "***REDACTED***" + secret[-2:]

    def _exclude_dir_regexes(self, context: dict) -> List[str]:
        """Directory-exclusion regexes for gitleaks/trufflehog, mirroring the file
        scanner's ignored dirs (node_modules, vendor, venv, target, Pods, ...) plus any
        `secret_checker.exclude_dirs` from config. Anchored on path separators so short
        names like 'bin' don't match unrelated paths. (The built-in python_regex tool
        already skips these because the file scanner prunes them.)"""
        from ..core.file_scanner import DEFAULT_IGNORE_DIRS
        dirs = set(context.get("ignore_dirs") or DEFAULT_IGNORE_DIRS)
        dirs |= set(self.config.get("exclude_dirs", []) or [])
        regexes = []
        for d in sorted(dirs):
            d = str(d).strip().strip("/\\")
            if d:
                regexes.append(r"(^|[/\\])" + re.escape(d) + r"([/\\]|$)")
        return regexes

    @staticmethod
    def _write_temp(text: str, prefix: str, suffix: str) -> str:
        """Write text to a temp file and return its path ('' if text is empty)."""
        if not text:
            return ""
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
        try:
            os.write(fd, text.encode("utf-8"))
        finally:
            os.close(fd)
        return path

    def _scan_with_trufflehog(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        """Runs trufflehog and parses the output."""
        self.findings = []
        # trufflehog excludes paths via a file of regexes passed to --exclude-paths.
        exclude_file = self._write_temp("\n".join(self._exclude_dir_regexes(context)), "th-exclude-", ".txt")
        try:
            # Trufflehog v3 scans the filesystem directly
            command = [resolve_command("trufflehog") or "trufflehog", "filesystem", str(root), "--json"]
            if exclude_file:
                command += ["--exclude-paths", exclude_file]
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True, timeout=300)
            
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    fs = finding['SourceMetadata']['Data']['Filesystem']
                    # Recent trufflehog includes a line number; older builds may not.
                    raw_line = fs.get('line')
                    th_line = int(raw_line) if isinstance(raw_line, (int, str)) and str(raw_line).isdigit() else None
                    self.add_finding(
                        severity=Severity.HIGH,
                        title=f"Trufflehog: {finding['DetectorName']}",
                        description=f"Secret detected in {fs['file']}",
                        recommendation=f"Found by detector: {finding['DetectorName']}",
                        file=self._rel_path(fs['file'], root),
                        line=th_line,
                        evidence=finding['Raw'],
                        tags=["secret", "trufflehog", finding['DetectorName'].lower().replace(" ", "_")],
                    )
                except (json.JSONDecodeError, KeyError) as e:
                    # Handle cases where a line is not valid JSON or missing keys
                    self.add_finding(
                        severity=Severity.WARNING,
                        title="Trufflehog output parsing error",
                        description=f"Could not parse a line of trufflehog output: {line[:100]}... Error: {e}",
                        recommendation="Check the trufflehog tool version and its output format.",
                        tags=["tool-failure", "trufflehog"]
                    )

        except FileNotFoundError:
            return [self._tool_not_found_finding("trufflehog")]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            self.add_finding(
                severity=Severity.WARNING,
                title="Trufflehog scan failed",
                description=f"Trufflehog execution failed: {getattr(e, 'stderr', e)}",
                recommendation="Ensure trufflehog is installed and functioning correctly.",
                tags=["tool-failure", "trufflehog"]
            )
        finally:
            if exclude_file:
                try:
                    os.unlink(exclude_file)
                except OSError:
                    pass
        return self.findings

    def _scan_with_trivy_secrets(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        """Run Trivy secret scanner as a second detection layer alongside gitleaks."""
        self.findings = []
        try:
            result = run_trivy(root, "secret")
        except RuntimeError:
            return [self._tool_not_found_finding("trivy")]

        if result is None:
            self.add_finding(
                severity=Severity.WARNING,
                title="Trivy secrets scan failed",
                description="Trivy ran but produced no output.",
                recommendation="Check that trivy is installed and can access the project directory.",
                tags=["tool-failure", "trivy"],
            )
            return self.findings

        for res in result.get("Results") or []:
            target = res.get("Target", "")
            for secret in res.get("Secrets") or []:
                rule = secret.get("RuleID", "secret")
                self.add_finding(
                    severity=Severity.HIGH,
                    title=f"Trivy: {secret.get('Title') or rule}",
                    description=f"Secret detected in {target} at line {secret.get('StartLine')}.",
                    recommendation=f"Rule '{rule}'. Rotate the secret and remove it from source.",
                    file=self._rel_path(target, root),
                    line=secret.get("StartLine"),
                    evidence=self._mask_value(secret.get("Match") or ""),
                    tags=["secret", "trivy", rule],
                )
        return self.findings

    def _tool_not_found_finding(self, tool_name: str) -> Finding:
        """Creates a Finding when a tool is not found."""
        return Finding(
            severity=Severity.WARNING,
            plugin=self.name,
            title=f"Tool not found: {tool_name}",
            description=f"The secret scanner was configured to use '{tool_name}', but it was not found in the system's PATH.",
            recommendation=f"Please install '{tool_name}' or change the secret_checker tool in your config file.",
            tags=["configuration", "tool-missing"],
        )


    def _check_high_entropy(
        self, lines: List[str], rel: str, path: Path, is_example: bool, seen: set
    ) -> None:
        """Flag high-entropy strings that may be undiscovered secrets."""
        # Only run on config/env/properties files to avoid flooding
        config_exts = {".env", ".yaml", ".yml", ".json", ".properties", ".ini", ".toml", ".tfvars"}
        if path.suffix.lower() not in config_exts and path.name not in {".env"}:
            return

        # Pattern to extract quoted string values
        value_pattern = re.compile(r"""[=:]\s*['"]([A-Za-z0-9+/\-_.~!@#$%^&*]{20,})['"]""")

        for line_num, line in enumerate(lines, 1):
            for match in value_pattern.finditer(line):
                val = match.group(1)
                entropy = shannon_entropy(val)
                if entropy >= ENTROPY_THRESHOLD and len(val) >= MIN_ENTROPY_LENGTH:
                    key = (rel, line_num, "high_entropy")
                    if key in seen:
                        continue
                    seen.add(key)
                    self.add_finding(
                        severity=Severity.LOW if is_example else Severity.MEDIUM,
                        title="High-entropy string detected (possible secret)",
                        description=(
                            f"A high-entropy string (entropy={entropy:.2f}) was found in "
                            f"'{rel}' at line {line_num}. This may be an undiscovered API key or password."
                        ),
                        recommendation=(
                            "Review this value. If it is a secret, move it to an environment variable "
                            "or secrets manager."
                        ),
                        file=rel,
                        line=line_num,
                        evidence=self._mask_secret(line, match),
                        tags=["secret", "high-entropy"],
                    )

    @staticmethod
    def _compile_patterns():
        return [(name, re.compile(pattern), severity, rec)
                for name, pattern, severity, rec in SECRET_PATTERNS]

    @staticmethod
    def _mask_secret(line: str, match: re.Match) -> str:
        """Partially mask the matched secret in the evidence string."""
        start, end = match.span()
        length = end - start
        if length <= 8:
            masked = "*" * length
        else:
            visible = max(4, length // 4)
            masked = match.group()[:visible] + "***REDACTED***"
        return line[:start] + masked + line[end:]
