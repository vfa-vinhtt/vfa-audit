"""
Report Engine: aggregates findings and generates JSON, Markdown, and HTML reports.
"""
from __future__ import annotations
import json
import datetime
from pathlib import Path
from typing import List, Dict, Any

from ..plugins.base_plugin import Finding, Severity
from .. import __version__ as TOOL_VERSION


SEVERITY_COUNTS_TEMPLATE = {s.value: 0 for s in Severity}

# Plugins whose findings are presented together in one report section. This is a
# PRESENTATION concern only — JSON output keeps each finding's real plugin name and
# the plugins still run/enable independently. Maps plugin -> (section, subgroup).
MERGED_SECTIONS = {
    "gitignore_checker": ("Environment & Gitignore", "Gitignore"),
    "env_checker": ("Environment & Gitignore", "Env Files"),
}


def resolve_group(plugin: str) -> tuple:
    """Map a finding's plugin string to (section_title, subgroup_title) for reports.

    Honors MERGED_SECTIONS; otherwise derives titles from the `plugin[:subtool]`
    convention (e.g. 'secret_checker:gitleaks' -> ('Secret Checker', 'Gitleaks')).
    Plugins with no sub-tool get the subgroup 'General'.
    """
    main, _, sub = plugin.partition(":")
    if main in MERGED_SECTIONS:
        return MERGED_SECTIONS[main]
    section = main.replace("_", " ").title()
    subgroup = sub.replace("_", " ").title() if sub else "General"
    return section, subgroup


class ReportEngine:
    def __init__(self, findings: List[Finding], project_info: dict, tool_info: List[Dict[str, Any]] = None, scanner_version: str = None):
        ordered = sorted(findings, key=lambda f: f.severity.order())
        self.findings = self._dedupe(ordered)
        self.project_info = project_info
        self.tool_info = tool_info or []
        self.scanner_version = scanner_version
        # Local timezone, no microseconds, space separator (still ISO-8601, e.g.
        # "2026-06-14 14:14:29+07:00"). astimezone() on a naive now() attaches the
        # machine's local tzinfo so the offset is shown.
        self.generated_at = (
            datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(sep=" ")
        )

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        """Collapse the SAME data point detected by multiple sub-tools into one finding.

        Two findings are the same data when they share (report section, file, line) but
        come from different sub-tools (e.g. secret_checker:gitleaks vs :trufflehog). The
        highest-severity one is kept (input is severity-sorted) and the other detectors
        are recorded on it so the report can highlight "also detected by ...". Findings
        without a file+line, or a genuine second hit from the SAME sub-tool, are never
        merged. Counts and the score then reflect deduplicated data, not raw tool hits.
        """
        def _norm(path: str) -> str:
            # Tools report paths inconsistently (\\ vs /, leading ./). Normalize so the
            # same file matches regardless of which tool reported it.
            p = path.replace("\\", "/")
            return p[2:] if p.startswith("./") else p

        def _record(primary: Finding, label: str) -> None:
            primary_label = resolve_group(primary.plugin)[1]
            if label != primary_label and label not in primary.also_detected_by:
                primary.also_detected_by.append(label)

        kept: List[Finding] = []
        by_key: Dict[tuple, Finding] = {}    # (section, file, line) -> kept primary
        by_file: Dict[tuple, Finding] = {}   # (section, file) -> first LINED primary
        by_title: Dict[tuple, Finding] = {}  # (section, title) -> primary for file-less findings
        for f in findings:
            section, label = resolve_group(f.plugin)
            if not f.file:
                # File-less findings (license policy, dependency advisories, summaries)
                # identify their data by title, not location. Collapse the same title
                # reported by a different sub-tool/method — e.g. the license `content`
                # path and a per-language license tool both emit
                # "Denied license: pkg (GPL-2.0-only)". Distinct items have distinct
                # titles (they embed the package/count), so this won't over-merge;
                # a genuine repeat from the SAME tool is kept.
                tkey = (section, f.title)
                primary = by_title.get(tkey)
                if primary is None:
                    kept.append(f)
                    by_title[tkey] = f
                elif primary.plugin != f.plugin:
                    _record(primary, label)
                else:
                    kept.append(f)
                continue
            nf = _norm(f.file)
            if f.line is not None:
                key = (section, nf, f.line)
                primary = by_key.get(key)
                if primary is None:
                    kept.append(f)
                    by_key[key] = f
                    by_file.setdefault((section, nf), f)
                elif primary.plugin == f.plugin:
                    kept.append(f)            # same tool, genuinely distinct hit on this line
                else:
                    _record(primary, label)   # same data, another sub-tool
            else:
                # No line (e.g. an older trufflehog): fold ONLY into an existing lined
                # primary for the same file. Never merge two line-less findings together —
                # that would collapse distinct secrets in one file.
                primary = by_file.get((section, nf))
                if primary is not None and primary.plugin != f.plugin:
                    _record(primary, label)
                else:
                    kept.append(f)
        for f in kept:
            f.also_detected_by.sort()
        return kept

    def _counts(self) -> Dict[str, int]:
        counts = {**SEVERITY_COUNTS_TEMPLATE}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    # Per-severity base penalty. The first finding of a tier costs the full weight;
    # each additional one costs progressively less (count ** _SCORE_EXPONENT), so the
    # score stays a meaningful gradient instead of slamming to 0 once a few criticals
    # appear (the old flat `100 - 20*n` design hit 0 at 5 criticals). INFO never counts.
    _SCORE_WEIGHTS = {
        Severity.CRITICAL: 25.0,
        Severity.HIGH: 12.0,
        Severity.MEDIUM: 4.0,
        Severity.WARNING: 2.5,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0,
    }
    _SCORE_EXPONENT = 0.7

    def _score(self) -> int:
        """Security score 0-100 (higher is better) with diminishing returns per tier."""
        counts = self._counts()
        penalty = 0.0
        for sev, weight in self._SCORE_WEIGHTS.items():
            n = counts.get(sev.value, 0)
            if weight and n:
                penalty += weight * (n ** self._SCORE_EXPONENT)
        return max(0, round(100 - penalty))

    def _section_summary(self) -> List[Dict[str, Any]]:
        """Per-report-section severity breakdown, built from the DEDUPLICATED findings.

        Each row: {section, counts{severity: n}, total, worst}. Sorted most-severe
        first, then larger sections first, so the most concerning areas surface on top.
        """
        acc: Dict[str, Dict[str, int]] = {}
        for f in self.findings:
            section = resolve_group(f.plugin)[0]
            counts = acc.setdefault(section, {s.value: 0 for s in Severity})
            counts[f.severity.value] += 1
        rows: List[Dict[str, Any]] = []
        for section, counts in acc.items():
            total = sum(counts.values())
            worst = next((s.value for s in Severity if counts[s.value]), Severity.INFO.value)
            rows.append({"section": section, "counts": counts, "total": total, "worst": worst})
        rows.sort(key=lambda r: (Severity(r["worst"]).order(), -r["total"]))
        return rows

    @staticmethod
    def _grade(score: int) -> str:
        """Letter grade for at-a-glance posture."""
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def to_dict(self) -> dict:
        counts = self._counts()
        score = self._score()
        return {
            "generated_at": self.generated_at,
            "tool_version": TOOL_VERSION,
            "score": score,
            "grade": self._grade(score),
            "project": self.project_info,
            "info": {"scanner_version": self.scanner_version, "tools": self.tool_info},
            "summary": counts,
            "sections": self._section_summary(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    # ── JSON ──────────────────────────────────────────────────────────────────

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    # ── Markdown ──────────────────────────────────────────────────────────────

    def to_markdown(self) -> str:
        counts = self._counts()
        score = self._score()
        proj = self.project_info
        lines = [
            f"# Security Scan Report — {proj.get('project_name', 'Unknown Project')}",
            f"",
            f"**Generated:** {self.generated_at}  ",
            f"**Scanner Version:** v{TOOL_VERSION}  ",
            f"**Score:** {score}/100 (Grade {self._grade(score)})  ",
            f"**Git Repo:** {proj.get('git_remote', 'N/A')}  ",
            f"**Branch:** {proj.get('git_branch', 'N/A')}  ",
            f"**Languages:** {', '.join(proj.get('languages', ['N/A']))}  ",
            f"**Framework:** {proj.get('framework', 'N/A')}  ",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in Severity:
            lines.append(f"| {sev.value} | {counts[sev.value]} |")
        lines.append("")
        lines.append(f"**Total Findings:** {len(self.findings)}")
        lines.append("")

        sections = self._section_summary()
        if sections:
            lines.append("## Security Summary by Section")
            lines.append("")
            lines.append("| Section | CRITICAL | HIGH | MEDIUM | WARNING | LOW | INFO | Total |")
            lines.append("|---------|----------|------|--------|---------|-----|------|-------|")
            for r in sections:
                c = r["counts"]
                lines.append(
                    f"| {r['section']} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | "
                    f"{c['WARNING']} | {c['LOW']} | {c['INFO']} | {r['total']} |"
                )
            lines.append("")

        # Group findings into report sections (related plugins are merged).
        by_section: Dict[str, Dict[str, List[Finding]]] = {}
        for f in self.findings:
            section, subgroup = resolve_group(f.plugin)
            by_section.setdefault(section, {}).setdefault(subgroup, []).append(f)

        for section_title, subgroups in by_section.items():
            lines.append(f"## {section_title}")
            lines.append("")
            for subgroup_title, plugin_findings in subgroups.items():
                if subgroup_title != "General":
                    lines.append(f"### {subgroup_title}")
                    lines.append("")

                for f in plugin_findings:
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "WARNING": "⚠️", "LOW": "🔵", "INFO": "⚪"}.get(f.severity.value, "•")
                    lines.append(f"#### {icon} [{f.severity.value}] {f.title}")
                    lines.append("")
                    lines.append(f"**Description:** {f.description}")
                    lines.append("")
                    lines.append(f"**Recommendation:** {f.recommendation}")
                    if f.file:
                        loc = f":{f.line}" if f.line else ""
                        lines.append(f"**File:** `{f.file}{loc}`")
                    if f.also_detected_by:
                        lines.append(f"**Also detected by:** {', '.join(f.also_detected_by)}")
                    if f.evidence:
                        lines.append(f"**Evidence:**")
                        lines.append(f"```")
                        lines.append(f.evidence)
                        lines.append(f"```")
                    lines.append("")

        return "\n".join(lines)

    def save_markdown(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown(), encoding="utf-8")

    # ── Console ───────────────────────────────────────────────────────────────

    def print_summary(self) -> None:
        counts = self._counts()
        score = self._score()
        proj = self.project_info

        W = "\033[0m"
        COLORS = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[33m",
            "MEDIUM": "\033[93m",
            "WARNING": "\033[38;5;214m",
            "LOW": "\033[94m",
            "INFO": "\033[90m",
        }
        BOLD = "\033[1m"

        print(f"\n{'─' * 60}")
        print(f"{BOLD}Security Scan Report{W}")
        print(f"{'─' * 60}")
        print(f"Project : {proj.get('project_name', 'Unknown')}")
        print(f"Repo    : {proj.get('git_remote', 'N/A')}")
        print(f"Branch  : {proj.get('git_branch', 'N/A')}")
        print(f"Language: {', '.join(proj.get('languages', ['N/A']))}")
        print(f"Scanner : v{TOOL_VERSION}")
        print(f"Score   : {BOLD}{score}/100{W}  (Grade {self._grade(score)})")
        print(f"{'─' * 60}")
        print(f"{'Severity':<12} {'Count':>6}")
        print(f"{'─' * 20}")
        for sev in Severity:
            c = COLORS.get(sev.value, "")
            print(f"{c}{sev.value:<12}{W} {counts[sev.value]:>6}")
        print(f"{'─' * 20}")
        print(f"{'TOTAL':<12} {len(self.findings):>6}")
        print(f"{'─' * 60}")

        # Print critical/high findings inline
        critical_high = [f for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if critical_high:
            print(f"\n{COLORS['CRITICAL']}{BOLD}Critical / High Findings:{W}")
            for f in critical_high:
                c = COLORS[f.severity.value]
                loc = f" @ {f.file}:{f.line}" if f.file and f.line else (f" @ {f.file}" if f.file else "")
                also = f"  (also: {', '.join(f.also_detected_by)})" if f.also_detected_by else ""
                print(f"  {c}[{f.severity.value}]{W} ({f.plugin}) {f.title}{loc}{also}")
        print()

    # ── HTML ──────────────────────────────────────────────────────────────────

    def to_html(self) -> str:
        from scanner.reports.html_template import render_html
        return render_html(self.to_dict(), self.project_info)

    def save_html(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_html(), encoding="utf-8")

    # ── Policy output (mirrors vinhtt-tool bash policy classification) ────────

    def save_policy_report(self, output_dir: Path) -> dict:
        """Write blockers.json, review-required.json, warnings.json, summary_policy.json.

        Policy verdict logic:
          FAIL            → any CRITICAL/HIGH finding, or a tool-failure finding
          REVIEW_REQUIRED → only MEDIUM findings remain (no blockers)
          WARNING         → only LOW/WARNING-severity findings remain
          PASS            → only INFO findings (or none)
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        blockers = [f for f in self.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        review_required = [f for f in self.findings if f.severity == Severity.MEDIUM]
        warnings_list = [f for f in self.findings if f.severity in (Severity.WARNING, Severity.LOW)]
        has_tool_error = any("tool-failure" in (f.tags or []) for f in self.findings)

        if blockers or has_tool_error:
            status = "FAIL"
        elif review_required:
            status = "REVIEW_REQUIRED"
        elif warnings_list:
            status = "WARNING"
        else:
            status = "PASS"

        def _dump(lst: list) -> str:
            return json.dumps([f.to_dict() for f in lst], indent=2, ensure_ascii=False)

        (output_dir / "blockers.json").write_text(_dump(blockers), encoding="utf-8")
        (output_dir / "review-required.json").write_text(_dump(review_required), encoding="utf-8")
        (output_dir / "warnings.json").write_text(_dump(warnings_list), encoding="utf-8")

        summary = {
            "generated_at": self.generated_at,
            "project": self.project_info,
            "status": status,
            "counts": {
                "blockers": len(blockers),
                "review_required": len(review_required),
                "warnings": len(warnings_list),
            },
            "tool_error_detected": has_tool_error,
        }
        (output_dir / "summary_policy.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return summary
