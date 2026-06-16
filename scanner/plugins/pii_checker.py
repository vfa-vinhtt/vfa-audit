"""
Plugin: PII Checker
Detects personally identifiable information (PII) hardcoded in source files:
email addresses, phone numbers, credit card numbers, SSNs, IBANs, etc.

False-positive controls:
  - documented dummy/test values are allowlisted (example.com, 555-01xx, test cards, sample SSNs);
  - structural validators (Luhn for cards, mod-97 for IBANs) reject random look-alikes;
  - ambiguous numeric patterns (phone/SSN) are confirmed by a nearby PII keyword, else downgraded;
  - the passport rule is keyword-gated instead of matching any "AB123456"-shaped token.

Config (plugins.pii_checker):
  disabled_categories: [list of pattern names to skip]
  allowlist: [list of regexes; any matching value is ignored]
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import List, Optional

from .base_plugin import BasePlugin, Finding, Severity

# (name, pattern, severity, recommendation, kind). `kind` drives validation/gating.
PII_PATTERNS = [
    ("Email Address",
     r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
     Severity.MEDIUM,
     "Remove real email addresses from source code. Use placeholder@example.com in tests.",
     "email"),
    ("Phone Number (US)",
     r"\b(?:\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b",
     Severity.MEDIUM,
     "Replace real phone numbers with dummy data (e.g. 555-0100 series).",
     "phone"),
    ("Phone Number (International)",
     r"\+\d{1,3}[\s\-.]?\d{1,4}[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}",
     Severity.MEDIUM,
     "Replace real international phone numbers with test data.",
     "phone"),
    ("US Social Security Number",
     r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
     Severity.CRITICAL,
     "SSNs are highly sensitive. Remove immediately and review data handling compliance (PII/HIPAA).",
     "ssn"),
    ("Credit Card Number",
     r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
     Severity.CRITICAL,
     "Credit card numbers must never appear in source code. This may violate PCI DSS.",
     "card"),
    ("IPv4 Address (non-private)",
     r"\b(?!(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\.\d)(?:\d{1,3}\.){3}\d{1,3}\b",
     Severity.LOW,
     "Public IP addresses in code may reveal infrastructure. Use configuration files or DNS names.",
     "ipv4"),
    ("Date of Birth Pattern",
     r"(?i)(?:dob|date_of_birth|birthdate|birth_date)\s*[=:]\s*['\"]?\d{1,2}[-/]\d{1,2}[-/]\d{2,4}['\"]?",
     Severity.HIGH,
     "Date of birth is PII. Remove from source code and never store without encryption.",
     "keyworded"),
    ("Passport Number",
     r"\b[A-Z]{1,2}\d{6,9}\b",
     Severity.HIGH,
     "Passport numbers are sensitive PII. Remove from source code.",
     "passport"),
    ("Driver License Pattern",
     r"(?i)(?:driver[_\s]?li[sc]ense|dl[_\s]?num(?:ber)?)\s*[=:]\s*['\"]?[A-Z0-9\-]{5,20}['\"]?",
     Severity.HIGH,
     "Driver license numbers are PII. Remove from source code.",
     "keyworded"),
    ("National ID / Tax ID",
     r"(?i)(?:national[_\s]?id|tax[_\s]?id|nid|tin|taxpayer)\s*[=:]\s*['\"]?\d[\d\-]{6,20}['\"]?",
     Severity.HIGH,
     "Tax/National IDs are sensitive PII. Remove from source code.",
     "keyworded"),
    ("IBAN (Bank Account)",
     r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b",
     Severity.CRITICAL,
     "IBAN / bank account numbers must not appear in source code. This may violate PCI DSS / PSD2.",
     "iban"),
    ("Health / Medical Record Number",
     r"(?i)(?:mrn|medical[_\s]?record|patient[_\s]?id|health[_\s]?id)\s*[=:]\s*['\"]?[A-Z0-9\-]{5,20}['\"]?",
     Severity.CRITICAL,
     "Medical record numbers are highly sensitive (HIPAA). Remove from source code immediately.",
     "keyworded"),
]

# Files/directories that are more likely test data — findings downgraded
TEST_MARKERS = {"test", "tests", "spec", "specs", "__tests__", "fixtures", "mocks",
                "mock", "fake", "stub", "stubs", "seed", "seeds", "example", "sample"}

SKIP_EXTENSIONS = {".min.js", ".min.css", ".map"}
SKIP_SUFFIX_SET = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".ttf", ".otf"}

# Keywords that confirm an ambiguous numeric match is really PII.
PII_KEYWORDS = (
    "ssn", "social security", "social_security", "socialsecurity", "phone", "mobile",
    "tel", "fax", "cell", "contact", "passport", "license", "licence", "dob",
    "birth", "name", "address", "card", "credit", "iban", "account", "patient",
    "customer", "national id", "national_id", "tax", "passenger", "applicant",
    "email", "e-mail", "e_mail", "user", "username", "recipient", "sender", "login",
)
PASSPORT_KEYWORDS = ("passport", "travel document", "document no", "document number")

# Documented dummy values that should never be flagged.
DUMMY_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "test.org",
    "domain.com", "yourdomain.com", "localhost",
}
DUMMY_EMAIL_MARKERS = ("noreply", "no-reply", "donotreply", "do-not-reply")
TEST_CARD_NUMBERS = {
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242",
    "5555555555554444", "5105105105105100", "5200828282828210",
    "378282246310005", "371449635398431", "6011111111111117", "6011000990139424",
    "3530111333300000", "3566002020360505", "30569309025904", "38520000023237",
}
SAMPLE_SSNS = {"078051120", "123456789", "219099999", "457555462", "000000000"}


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not digits:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _iban_valid(value: str) -> bool:
    """Validate an IBAN via the ISO 7064 mod-97 checksum (rejects random look-alikes)."""
    s = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", s) or not (15 <= len(s) <= 34):
        return False
    rearranged = s[4:] + s[:4]
    converted = "".join(str(int(c, 36)) if c.isalpha() else c for c in rearranged)
    try:
        return int(converted) % 97 == 1
    except ValueError:
        return False


def _has_pii_keyword(line: str) -> bool:
    low = line.lower()
    return any(k in low for k in PII_KEYWORDS)


class PIIChecker(BasePlugin):
    name = "pii_checker"
    description = "Detects PII (emails, phone numbers, SSNs, credit cards, etc.) in source code"

    def scan(self, root: Path, files: List[Path], context: dict) -> List[Finding]:
        self.findings = []
        disabled = set(self.config.get("disabled_categories", []) or [])
        allowlist = [re.compile(p) for p in (self.config.get("allowlist", []) or [])]
        # "high" (default) reports only validated / context-confirmed PII; "low" reports
        # every match (the old behavior). Bulk threshold flags data-dump-like files.
        min_conf = str(self.config.get("min_confidence", "high")).lower()
        bulk_threshold = max(2, int(self.config.get("bulk_threshold", 6)))
        compiled = [(name, re.compile(pat), sev, rec, kind)
                    for name, pat, sev, rec, kind in PII_PATTERNS if name not in disabled]

        seen = set()
        for f in files:
            suffix = f.suffix.lower()
            if suffix in SKIP_SUFFIX_SET or suffix in SKIP_EXTENSIONS:
                continue

            is_test = any(m in p.lower() for p in set(f.parts) for m in TEST_MARKERS)
            lines = self._read_lines(f)
            rel = str(f.relative_to(root))
            bulk_low: dict = {}  # kind -> count of suppressed low-confidence email/phone matches

            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("//", "#", "*", "<!--", "--")):
                    continue

                for pname, regex, severity, rec, kind in compiled:
                    for match in regex.finditer(line):
                        value = match.group()
                        if any(a.search(value) for a in allowlist):
                            continue

                        result = self._evaluate(kind, value, line, severity)
                        if result is None:
                            continue
                        sev, confidence = result

                        if confidence == "low" and kind in ("email", "phone"):
                            bulk_low[kind] = bulk_low.get(kind, 0) + 1

                        # Quiet default: only high-confidence PII (validated, or confirmed
                        # by nearby PII context). Low-confidence bare matches are noise.
                        if min_conf == "high" and confidence != "high":
                            continue

                        key = (rel, line_num, pname, value[:20])
                        if key in seen:
                            continue
                        seen.add(key)

                        if is_test and sev in (Severity.MEDIUM, Severity.HIGH):
                            sev = Severity.LOW

                        self.add_finding(
                            severity=sev,
                            title=f"PII detected: {pname}",
                            description=(
                                f"{pname} found in '{rel}' at line {line_num}."
                                + (" (test/mock file — verify this is synthetic data)" if is_test else "")
                                + ("" if confidence == "high" else " (low confidence — no PII context nearby)")
                            ),
                            recommendation=rec,
                            file=rel,
                            line=line_num,
                            evidence=self._mask_pii(line, match),
                            tags=["pii", pname.lower().replace(" ", "_"), f"{confidence}-confidence"],
                        )

            # Bulk heuristic: many bare emails/phones in one file usually means a real
            # dataset (e.g. an exported CSV/SQL dump). Surface ONE file-level finding even
            # in the default mode where the individual low-confidence ones are suppressed.
            if min_conf == "high":
                for kind, count in bulk_low.items():
                    if count >= bulk_threshold:
                        label = "email addresses" if kind == "email" else "phone numbers"
                        self.add_finding(
                            severity=Severity.LOW if is_test else Severity.MEDIUM,
                            title=f"{count} {label} in one file - possible real user data",
                            description=(
                                f"'{rel}' contains {count} {label}, which often indicates a real "
                                "dataset (e.g. an exported CSV/SQL dump) rather than incidental values."
                            ),
                            recommendation="Confirm this is synthetic data; never commit real user PII.",
                            file=rel,
                            tags=["pii", kind, "bulk"],
                        )

        if not self.findings:
            self.add_finding(
                severity=Severity.INFO,
                title="No PII patterns detected in source code",
                description="No obvious PII patterns were found. Ensure data is anonymized in tests.",
                recommendation=(
                    "Use libraries like Faker for generating synthetic test data "
                    "instead of real user data."
                ),
                tags=["pii"],
            )
        return self.findings

    def _evaluate(self, kind: str, value: str, line: str, severity: Severity):
        """Validate/gate a match. Returns (severity, confidence) where confidence is
        'high' (validated or context-confirmed) or 'low' (bare match), or None to skip."""
        digits = re.sub(r"\D", "", value)
        # Keyword check must look at the line WITHOUT the matched value, so an email's
        # own domain (gmail.com, ...) or a phone's digits don't self-confirm.
        context = line.replace(value, " ")

        if kind == "email":
            if self._is_dummy_email(value):
                return None
            return (severity, "high" if _has_pii_keyword(context) else "low")

        if kind == "card":
            if not _luhn_check(value) or digits in TEST_CARD_NUMBERS:
                return None
            return (severity, "high")  # Luhn-validated

        if kind == "iban":
            return (severity, "high") if _iban_valid(value) else None  # mod-97 validated

        if kind == "ipv4":
            if value.startswith(("127.", "0.")):
                return None
            if any(int(p) > 255 for p in value.split(".") if p.isdigit()):
                return None  # version string, not an IP
            return (severity, "low")  # infra info, weak PII signal

        if kind == "phone":
            if self._is_fictional_phone(value, digits):
                return None
            return (severity, "high" if _has_pii_keyword(context) else "low")

        if kind == "ssn":
            if digits in SAMPLE_SSNS or len(set(digits)) <= 1:
                return None
            if _has_pii_keyword(context):
                return (severity, "high")  # CRITICAL, context-confirmed
            # No keyword: dashed/spaced shape is notable but unconfirmed; raw 9 digits is noise.
            return (Severity.HIGH, "low") if ("-" in value or " " in value) else None

        if kind == "passport":
            low = context.lower()
            return (severity, "high") if any(k in low for k in PASSPORT_KEYWORDS) else None

        return (severity, "high")  # keyworded patterns (regex already self-gates)

    @staticmethod
    def _is_dummy_email(value: str) -> bool:
        low = value.lower()
        domain = low.rsplit("@", 1)[-1]
        return (
            domain in DUMMY_EMAIL_DOMAINS
            or domain.startswith(("example.", "test."))
            or any(m in low for m in DUMMY_EMAIL_MARKERS)
        )

    @staticmethod
    def _is_fictional_phone(value: str, digits: str) -> bool:
        if len(set(digits)) <= 1:  # all same digit
            return True
        if re.search(r"555[\s\-.]?01\d{2}", value):  # reserved fictional 555-01xx
            return True
        return digits in {"1234567890", "0000000000", "11234567890"}

    @staticmethod
    def _mask_pii(line: str, match: re.Match) -> str:
        """Partially mask PII in evidence."""
        start, end = match.span()
        original = match.group()
        if len(original) <= 4:
            masked = "****"
        else:
            masked = original[:2] + "****" + original[-2:]
        return line[:start] + masked + line[end:]
