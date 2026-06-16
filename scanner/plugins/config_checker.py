"""
Plugin: Config Checker
Detects security issues in configuration files:
- Hardcoded credentials in YAML, JSON, XML, .properties, .toml, .ini
- Debug/development settings left in production configs
- Insecure default configurations
- Missing security headers config
- Weak cryptographic settings
"""
from __future__ import annotations
import re
import json
from pathlib import Path
from typing import List, Set

from .base_plugin import BasePlugin, Finding, Severity

CONFIG_EXTENSIONS: Set[str] = {
    ".yaml", ".yml", ".json", ".xml", ".properties", ".toml",
    ".ini", ".cfg", ".conf", ".config",
}

# Patterns that indicate dangerous config values
DANGEROUS_CONFIG_PATTERNS = [
    # Debug mode
    (r"(?i)debug\s*[=:]\s*(true|1|yes|on)\b", Severity.HIGH,
     "Debug mode enabled in config",
     "Disable debug mode in production. It may expose stack traces, internal paths, and sensitive data."),

    # SSL/TLS disabled
    (r"(?i)(?:ssl|tls)[_\-]?verify\s*[=:]\s*(false|0|no|off)\b", Severity.CRITICAL,
     "SSL/TLS certificate verification disabled",
     "Never disable SSL verification. It enables MITM attacks. Fix the underlying certificate issue instead."),
    (r"(?i)verify[_\-]?ssl\s*[=:]\s*(false|0|no|off)\b", Severity.CRITICAL,
     "SSL verification disabled",
     "Enable SSL verification. Use properly signed certificates."),
    (r"(?i)insecure[_\-]?(?:skip[_\-]?verify|mode)\s*[=:]\s*(true|1|yes)\b", Severity.CRITICAL,
     "Insecure skip verify enabled",
     "Never skip TLS verification in production."),

    # Weak cryptography
    (r"(?i)(?:algorithm|cipher|crypto)\s*[=:]\s*['\"]?(md5|sha1|des|3des|rc4|rc2)\b", Severity.HIGH,
     "Weak cryptographic algorithm in config",
     "Use strong algorithms: SHA-256+, AES-256, TLS 1.2+. Avoid MD5, SHA1, DES, RC4."),

    # Weak TLS versions
    (r"(?i)(?:tls|ssl)[_\-]?(?:version|protocol)\s*[=:]\s*['\"]?(?:tls|ssl)?[_\-]?(?:1\.0|1\.1|ssl[23]|sslv2|sslv3)\b", Severity.HIGH,
     "Weak TLS/SSL version configured",
     "Require TLS 1.2 or higher. Disable TLS 1.0, TLS 1.1, and all SSL versions."),

    # CORS wildcard
    (r"(?i)(?:allow[_\-]?origin|cors[_\-]?origin)\s*[=:]\s*['\"]?\*['\"]?", Severity.HIGH,
     "CORS wildcard (*) configured",
     "Restrict CORS to specific allowed origins instead of using wildcard '*'."),

    # Admin/root credentials
    (r"(?i)(?:admin|root|superuser)[_\-]?(?:password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{1,}['\"]", Severity.CRITICAL,
     "Admin/root password hardcoded in config",
     "Remove hardcoded admin credentials. Use environment variables or a secrets manager."),

    # Default credentials
    (r"(?i)password\s*[=:]\s*['\"](?:password|admin|root|123456|qwerty|test|demo|default|changeme|secret)['\"]", Severity.CRITICAL,
     "Default/weak password in config",
     "Use strong, unique passwords. Never use default passwords in any environment."),

    # Open bind addresses
    (r"(?i)(?:bind[_\-]?address|host|listen)\s*[=:]\s*['\"]?0\.0\.0\.0['\"]?", Severity.MEDIUM,
     "Service bound to 0.0.0.0 (all interfaces)",
     "Bind services to localhost (127.0.0.1) or specific interfaces unless external access is intentional."),

    # Unrestricted file upload paths
    (r"(?i)(?:upload[_\-]?(?:path|dir|directory))\s*[=:]\s*['\"]?/(?:tmp|var/www|public)['\"]?", Severity.MEDIUM,
     "Potentially unsafe upload path configured",
     "Validate file uploads server-side. Store outside the web root. Enforce file type restrictions."),

    # Hardcoded secret key
    (r"(?i)secret[_\-]?key\s*[=:]\s*['\"][^\s'\"]{8,}['\"]", Severity.HIGH,
     "Secret key hardcoded in config",
     "Move secret keys to environment variables. Generate cryptographically random keys."),

    # JWT algorithm none
    (r"(?i)(?:jwt[_\-]?)?algorithm\s*[=:]\s*['\"]?none['\"]?", Severity.CRITICAL,
     "JWT algorithm set to 'none'",
     "Never use 'none' as a JWT algorithm. Use RS256 or HS256 with a strong secret."),

    # Open database permissions
    (r"(?i)(?:db[_\-]?|database[_\-]?)(?:user|username)\s*[=:]\s*['\"]?root['\"]?", Severity.HIGH,
     "Database configured to run as root",
     "Use a dedicated database user with minimal required permissions. Never use root."),

    # Log level verbose
    (r"(?i)log[_\-]?level\s*[=:]\s*['\"]?(?:debug|trace|verbose|all)['\"]?", Severity.LOW,
     "Verbose logging level in config",
     "Set log level to INFO or WARNING in production to avoid logging sensitive data."),

    # Exposed management endpoints
    (r"(?i)(?:management[_\-]?port|actuator|admin[_\-]?port)\s*[=:]\s*(?!0\b)\d{2,5}", Severity.MEDIUM,
     "Management/admin port exposed in config",
     "Restrict management endpoints to localhost or internal networks. Use authentication."),
]


class ConfigChecker(BasePlugin):
    name = "config_checker"
    description = "Detects insecure settings in configuration files"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        compiled = [(re.compile(p), sev, title, rec) for p, sev, title, rec in DANGEROUS_CONFIG_PATTERNS]

        seen = set()

        for f in files:
            if f.suffix.lower() not in CONFIG_EXTENSIONS:
                continue

            lines = self._read_lines(f)
            rel = str(f.relative_to(root))
            content = "\n".join(lines)

            for regex, severity, title, rec in compiled:
                for m in regex.finditer(content):
                    # Calculate line number
                    line_num = content[:m.start()].count("\n") + 1
                    key = (rel, line_num, title)
                    if key in seen:
                        continue
                    seen.add(key)

                    self.add_finding(
                        severity=severity,
                        title=title,
                        description=f"Found in '{rel}' at line {line_num}: {title}.",
                        recommendation=rec,
                        file=rel,
                        line=line_num,
                        evidence=self._truncate(lines[line_num - 1] if line_num <= len(lines) else m.group()),
                        tags=["config", severity.value.lower()],
                    )

            # Check JSON specifically for nested credential patterns
            if f.suffix.lower() == ".json":
                self._check_json_config(f, rel, seen)

        if not self.findings:
            self.add_finding(
                severity=Severity.INFO,
                title="No insecure configuration patterns detected",
                description="Configuration files passed the automated security checks.",
                recommendation=(
                    "Continue reviewing configs manually before deployment. "
                    "Ensure production configs use environment variables for all secrets."
                ),
                tags=["config"],
            )

        return self.findings

    def _check_json_config(self, f: Path, rel: str, seen: set) -> None:
        """Deep-check JSON config for nested credential keys."""
        sensitive_keys = {
            "password", "passwd", "pwd", "secret", "api_key", "apikey",
            "access_key", "private_key", "auth_token", "client_secret",
            "database_password", "db_password", "redis_password",
        }
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            self._walk_json(data, rel, sensitive_keys, seen)
        except (json.JSONDecodeError, OSError):
            pass

    def _walk_json(self, node, rel: str, sensitive_keys: set, seen: set, path: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                full_path = f"{path}.{k}" if path else k
                if k.lower() in sensitive_keys and isinstance(v, str) and v.strip():
                    # Skip obvious placeholders
                    placeholder_patterns = {"your_", "xxx", "<", "{", "$", "placeholder", "changeme", "todo"}
                    if not any(p in v.lower() for p in placeholder_patterns) and len(v) > 3:
                        key = (rel, full_path, "json_credential")
                        if key not in seen:
                            seen.add(key)
                            self.add_finding(
                                severity=Severity.HIGH,
                                title=f"Potential credential in JSON config: '{k}'",
                                description=(
                                    f"JSON key '{full_path}' in '{rel}' contains a non-empty value "
                                    "that may be a hardcoded credential."
                                ),
                                recommendation=(
                                    "Replace this value with an environment variable reference. "
                                    "Use configuration management that supports secret injection."
                                ),
                                file=rel,
                                evidence=f"{k}: {'*' * min(len(v), 8)}…",
                                tags=["config", "credential", "json"],
                            )
                self._walk_json(v, rel, sensitive_keys, seen, full_path)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk_json(item, rel, sensitive_keys, seen, f"{path}[{i}]")
