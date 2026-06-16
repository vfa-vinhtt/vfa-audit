"""
Plugin: Gitignore Checker
Verifies that sensitive files and patterns are properly listed in .gitignore.

Two kinds of check:
  1. Recommended patterns — are sensitive patterns present in .gitignore? The set
     is *context-aware*: Terraform/Java-keystore patterns are only required when the
     project actually uses those technologies, which avoids flooding (e.g.) a plain
     Node app with irrelevant findings.
  2. Dangerous files — is a sensitive file actually committed (git-tracked), or, when
     git state is unavailable, present on disk and NOT covered by .gitignore (i.e. it
     would be committed)? A present-but-ignored file is safe and is not flagged.
"""
from __future__ import annotations
import fnmatch
from pathlib import Path
from typing import List, Set, Tuple

from .base_plugin import BasePlugin, Finding, Severity
from ..utils.gitignore_utils import parse_gitignore, path_is_ignored, pattern_is_covered

# (pattern, description, severity) — required for every project
ALWAYS_REQUIRED: List[Tuple[str, str, Severity]] = [
    (".env", ".env file", Severity.CRITICAL),
    (".env.*", ".env variant files (e.g. .env.local)", Severity.HIGH),
    ("*.pem", "PEM private key / certificate files", Severity.CRITICAL),
    ("*.key", "Private key files", Severity.CRITICAL)
]

# (pattern, description, severity, condition) — required only when `condition`
# is in the set of detected project conditions.
CONDITIONAL_REQUIRED: List[Tuple[str, str, Severity, str]] = [
    ("node_modules/", "Node.js modules directory", Severity.LOW, "node"),
    ("npm-debug.log*", "npm debug logs", Severity.LOW, "node"),
    ("*.p12", "PKCS#12 certificate files", Severity.HIGH, "java"),
    ("*.jks", "Java KeyStore files", Severity.HIGH, "java"),
    ("*.keystore", "Keystore files", Severity.HIGH, "java"),
    ("terraform.tfvars", "Terraform variables (may contain secrets)", Severity.HIGH, "terraform"),
    ("*.tfstate", "Terraform state files (contain real infra details)", Severity.HIGH, "terraform"),
    ("*.tfstate.backup", "Terraform state backup", Severity.HIGH, "terraform"),
    (".terraform/", "Terraform working directory", Severity.MEDIUM, "terraform"),
    ("*.sql", "SQL dump files (may contain data)", Severity.MEDIUM, "sqldump"),
    ("*.dump", "Database dump files", Severity.MEDIUM, "sqldump"),
]

# Sensitive files that must never be committed (matched by filename).
# NOTE: .env files are intentionally NOT listed here - env_checker is the single
# authoritative reporter for .env exposure (it knows populated/committed/ignored state).
DANGEROUS_FILES: List[Tuple[str, Severity, str]] = [
    ("id_rsa", Severity.CRITICAL, "SSH private key should never be committed."),
    ("id_ed25519", Severity.CRITICAL, "SSH private key should never be committed."),
    ("*.pem", Severity.CRITICAL, "Private certificates should never be committed."),
    ("*.key", Severity.CRITICAL, "Private keys should never be committed."),
    ("*.p12", Severity.HIGH, "PKCS#12 bundles should never be committed."),
    ("*.keystore", Severity.HIGH, "Keystores should never be committed."),
    ("*secret*", Severity.HIGH, "Files named like secrets should never be committed."),
    ("*credential*", Severity.HIGH, "Credential files should never be committed."),
    ("terraform.tfvars", Severity.HIGH, "Terraform tfvars may contain secrets."),
    ("*.tfstate", Severity.HIGH, "Terraform state contains real infrastructure details."),
]


class GitignoreChecker(BasePlugin):
    name = "gitignore_checker"
    description = "Verifies sensitive patterns are covered by .gitignore"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        gitignore_path = root / ".gitignore"

        if not gitignore_path.exists():
            self.add_finding(
                severity=Severity.CRITICAL,
                title="No .gitignore file found",
                description=(
                    "The project has no .gitignore file. Sensitive files like .env, "
                    "private keys, and secrets could be accidentally committed."
                ),
                recommendation=(
                    "Create a .gitignore file and add at minimum:\n"
                    "  .env\n  .env.*\n  !.env.example\n  *.pem\n  *.key\n  *.log\n  node_modules/"
                ),
                tags=["gitignore", "critical"],
            )
            return self.findings

        patterns, negations = parse_gitignore(gitignore_path)
        # Expose positive entries for any plugin that still reads the old key.
        context["gitignore_entries"] = patterns

        conditions = self._detect_conditions(files, context)
        required = list(ALWAYS_REQUIRED) + [
            (pat, desc, sev)
            for pat, desc, sev, cond in CONDITIONAL_REQUIRED
            if cond in conditions
        ]

        # Is a real (non-template) .env file actually present? A missing .env rule is
        # an ACTIVE exposure when one exists, but only preventative when none does.
        env_present = any(
            (f.name == ".env" or f.name.startswith(".env."))
            and "example" not in f.name.lower() and "sample" not in f.name.lower()
            for f in files
        )

        covered = 0
        missing = []
        for pattern, description, severity in required:
            if pattern_is_covered(pattern, patterns):
                covered += 1
            else:
                missing.append((pattern, description, severity))

        for pattern, description, severity in sorted(missing, key=lambda x: x[2].order()):
            if pattern in (".env", ".env.*"):
                if env_present:
                    # A real .env file exists: env_checker is the authoritative reporter
                    # for its exposure (CRITICAL/HIGH, with populated/committed detail), so
                    # skip here to avoid duplicate findings in the same report section.
                    continue
                # No .env file yet -> preventative only.
                severity = Severity.MEDIUM
                description = (
                    f"'{pattern}' is not covered by .gitignore. No .env file exists yet, but adding "
                    "this rule now prevents secrets from being committed later."
                )
                recommendation = f"Add '{pattern}' to your .gitignore file."
            else:
                description = (
                    f"The pattern '{pattern}' ({description}) is not covered by .gitignore. "
                    "This could allow sensitive files to be accidentally committed."
                )
                recommendation = f"Add '{pattern}' to your .gitignore file."

            self.add_finding(
                severity=severity,
                title=f"Pattern not in .gitignore: {pattern}",
                description=description,
                recommendation=recommendation,
                file=".gitignore",
                tags=["gitignore", severity.value.lower()],
            )

        self._check_dangerous_files(root, files, context, patterns, negations)

        if not missing:
            self.add_finding(
                severity=Severity.INFO,
                title=".gitignore covers all required security patterns",
                description=f"All {covered} applicable patterns are present in .gitignore.",
                recommendation="Periodically review .gitignore as the project evolves.",
                file=".gitignore",
                tags=["gitignore"],
            )

        return self.findings

    def _check_dangerous_files(
        self, root: Path, files: List[Path], context: dict,
        patterns: Set[str], negations: Set[str],
    ) -> None:
        is_repo = context.get("is_git_repo", False)
        tracked = context.get("git_tracked_files", set())
        seen: Set[str] = set()

        for pattern, severity, note in DANGEROUS_FILES:
            for f in files:
                if not fnmatch.fnmatch(f.name.lower(), pattern.lower()):
                    continue
                rel = str(f.relative_to(root))
                rel_posix = rel.replace("\\", "/")
                if rel_posix in seen:
                    continue

                if is_repo:
                    # Definitive: only files actually tracked by git are a problem.
                    if rel_posix not in tracked:
                        continue
                    status = "is committed to git"
                    remediation = (
                        f"1. Run: git rm --cached {rel}\n"
                        f"2. Add a matching rule (e.g. '{pattern}') to .gitignore.\n"
                        "3. The file remains in git history — rotate any exposed secrets "
                        "and consider scrubbing history (git filter-repo / BFG)."
                    )
                else:
                    # No git data: a file is risky only if it is NOT already ignored
                    # (i.e. it would be committed on the next `git add`).
                    if path_is_ignored(rel_posix, patterns, negations):
                        continue
                    status = "is present and not covered by .gitignore (it would be committed)"
                    remediation = (
                        f"1. Add a matching rule (e.g. '{pattern}') to .gitignore.\n"
                        f"2. If it was already committed, run: git rm --cached {rel}\n"
                        "3. Rotate any secrets the file may contain."
                    )

                seen.add(rel_posix)
                self.add_finding(
                    severity=severity,
                    title=f"Sensitive file at risk: {f.name}",
                    description=f"The file '{rel}' matches '{pattern}' and {status}. {note}",
                    recommendation=remediation,
                    file=rel,
                    tags=["gitignore", "dangerous-file"],
                )

    @staticmethod
    def _detect_conditions(files: List[Path], context: dict) -> Set[str]:
        """Determine which conditional pattern groups are relevant to this project."""
        langs = {l.lower() for l in context.get("project_info", {}).get("languages", [])}
        exts: Set[str] = set()
        names: Set[str] = set()
        for f in files:
            exts.add(f.suffix.lower())
            names.add(f.name.lower())

        conditions: Set[str] = set()
        if "node.js" in langs or "package.json" in names:
            conditions.add("node")
        if (
            "java" in langs or "kotlin" in langs
            or {".jks", ".keystore", ".gradle"} & exts
            or "pom.xml" in names
        ):
            conditions.add("java")
        if {".tf", ".tfvars", ".tfstate"} & exts:
            conditions.add("terraform")
        if {".sql", ".dump"} & exts:
            conditions.add("sqldump")
        return conditions
