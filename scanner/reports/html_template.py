"""
HTML report renderer — self-contained single-file HTML output.
"""
from __future__ import annotations
import html
from typing import List, Dict

from ..core.report_engine import resolve_group


SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e67e22",
    "MEDIUM": "#f39c12",
    "WARNING": "#f1c40f",
    "LOW": "#2980b9",
    "INFO": "#7f8c8d",
}

SEVERITY_BG = {
    "CRITICAL": "#fdf0ef",
    "HIGH": "#fef5ec",
    "MEDIUM": "#fefaec",
    "WARNING": "#fefcec",
    "LOW": "#eaf4fb",
    "INFO": "#f4f6f7",
}


def _esc(s) -> str:
    return html.escape(str(s)) if s else ""


def _slug(s) -> str:
    """Stable DOM id for a section title (same input on the summary row and the
    findings section, so the click target always matches). 'Environment & Gitignore'
    -> 'sec-environment-gitignore'."""
    slug = "".join(ch if ch.isalnum() else "-" for ch in str(s).lower())
    while "--" in slug:
        slug = slug.replace("--", "-")
    return "sec-" + slug.strip("-")


def _score_color(score: int) -> str:
    if score >= 80:
        return "#27ae60"
    if score >= 60:
        return "#f39c12"
    if score >= 40:
        return "#e67e22"
    return "#c0392b"


def render_html(data: dict, project_info: dict) -> str:
    findings = data["findings"]
    counts = data["summary"]
    score = data["score"]
    grade = data.get("grade", "")
    total = data["total_findings"]
    generated_at = data["generated_at"]

    # Group findings into report sections (related plugins are merged).
    by_section: Dict[str, Dict[str, List[dict]]] = {}
    for f in findings:
        section, subgroup = resolve_group(f["plugin"])
        by_section.setdefault(section, {}).setdefault(subgroup, []).append(f)

    # Build findings HTML
    findings_html_parts = []
    for main_label, sub_plugins in by_section.items():
        subgroup_html_parts = []
        total_findings_in_group = 0

        for sub_label, plugin_findings in sub_plugins.items():
            total_findings_in_group += len(plugin_findings)

            cards = []
            for f in plugin_findings:
                sev = f["severity"]
                color = SEVERITY_COLORS.get(sev, "#7f8c8d")
                bg = SEVERITY_BG.get(sev, "#f4f6f7")
                file_html = ""
                if f.get("file"):
                    loc = f":{f['line']}" if f.get("line") else ""
                    file_html = f'<p class="finding-file">📄 <code>{_esc(f["file"])}{loc}</code></p>'
                also_html = ""
                if f.get("also_detected_by"):
                    tools = ", ".join(_esc(t) for t in f["also_detected_by"])
                    also_html = f'<p class="also-detected">🔁 Also detected by: {tools}</p>'
                evidence_html = ""
                if f.get("evidence"):
                    evidence_html = (
                        f'<div class="evidence"><strong>Evidence:</strong>'
                        f'<pre><code>{_esc(f["evidence"])}</code></pre></div>'
                    )
                tags_html = " ".join(
                    f'<span class="tag">{_esc(t)}</span>' for t in (f.get("tags") or [])
                )
                cards.append(f"""
                <div class="finding-card" style="border-left: 4px solid {color}; background: {bg};">
                    <div class="finding-header">
                        <span class="badge" style="background:{color}">{_esc(sev)}</span>
                        <strong class="finding-title">{_esc(f["title"])}</strong>
                    </div>
                    <p class="finding-desc">{_esc(f["description"])}</p>
                    {file_html}
                    {also_html}
                    <div class="finding-rec">💡 <em>{_esc(f["recommendation"])}</em></div>
                    {evidence_html}
                    <div class="tags">{tags_html}</div>
                </div>""")

            subgroup_html_parts.append(f"""
            <section class="plugin-section subgroup">
                <h3 class="plugin-title subgroup-title" onclick="toggleSection(this)">
                    ▾ {_esc(sub_label)}
                    <span class="plugin-count">{len(plugin_findings)} finding(s)</span>
                </h3>
                <div class="plugin-body">
                    {''.join(cards)}
                </div>
            </section>""")

        findings_html_parts.append(f"""
        <section class="plugin-section" id="{_slug(main_label)}">
            <h2 class="plugin-title" onclick="toggleSection(this)">
                ▾ {main_label}
                <span class="plugin-count">{total_findings_in_group} finding(s)</span>
            </h2>
            <div class="plugin-body">
                {''.join(subgroup_html_parts)}
            </div>
        </section>""")

    # Summary bars
    summary_bars = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW", "INFO"]:
        count = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        summary_bars.append(f"""
        <div class="summary-item">
            <span class="sev-label" style="color:{color}">{sev}</span>
            <div class="bar-wrap">
                <div class="bar" style="width:{min(100, count * 5)}%; background:{color}"></div>
            </div>
            <span class="sev-count" style="color:{color}">{count}</span>
        </div>""")

    # Per-section severity summary table (built from the deduplicated findings).
    SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW", "INFO"]
    section_rows = []
    for row in data.get("sections", []):
        worst_color = SEVERITY_COLORS.get(row.get("worst", "INFO"), "#7f8c8d")
        cells = []
        for sev in SEV_ORDER:
            n = row["counts"].get(sev, 0)
            if n:
                cells.append(f'<td class="num" style="color:{SEVERITY_COLORS[sev]};font-weight:700">{n}</td>')
            else:
                cells.append('<td class="num zero">0</td>')
        section_rows.append(f"""
        <tr class="sec-row" style="border-left:4px solid {worst_color}" onclick="goToSection('{_slug(row["section"])}')" title="Jump to {_esc(row["section"])}">
          <td class="sec-name">{_esc(row["section"])} <span class="jump">↧</span></td>
          {''.join(cells)}
          <td class="num sec-total">{row["total"]}</td>
        </tr>""")
    section_summary_html = ""
    if section_rows:
        header_cells = "".join(f'<th class="num">{s.title()}</th>' for s in SEV_ORDER)
        section_summary_html = f"""
  <div class="section-summary">
    <h3>Security Summary by Section</h3>
    <div class="sec-table-wrap">
      <table class="sec-table">
        <thead><tr><th>Section</th>{header_cells}<th class="num">Total</th></tr></thead>
        <tbody>{''.join(section_rows)}</tbody>
      </table>
    </div>
  </div>"""

    sc_color = _score_color(score)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {_esc(project_info.get("project_name", "Project"))}</title>
<style>
  :root {{
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --bg: #f8f9fa; --card: #fff; --border: #e0e0e0;
    --text: #2c3e50; --muted: #7f8c8d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: var(--font); background: var(--bg); color: var(--text); padding: 0 0 40px; }}
  header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #fff; padding: 32px 40px; }}
  header h1 {{ font-size: 1.8rem; font-weight: 700; }}
  header .meta {{ margin-top: 12px; opacity: .75; font-size: .9rem; line-height: 1.9;
    overflow-wrap: anywhere; word-break: break-word; }}
  .container {{ max-width: 1100px; margin: 32px auto; padding: 0 20px; }}
  .score-row {{ display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }}
  .score-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 24px 32px; flex: 1; min-width: 200px; text-align: center; }}
  .score-num {{ font-size: 3rem; font-weight: 800; color: {sc_color}; }}
  .score-label {{ font-size: .85rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; }}
  .summary-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 24px 28px; flex: 2; min-width: 300px; }}
  .summary-card h3 {{ font-size: 1rem; margin-bottom: 16px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
  .summary-item {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
  .sev-label {{ width: 75px; font-weight: 600; font-size: .85rem; }}
  .bar-wrap {{ flex: 1; height: 8px; background: #f0f0f0; border-radius: 4px; overflow: hidden; }}
  .bar {{ height: 100%; border-radius: 4px; min-width: 3px; transition: width .5s; }}
  .sev-count {{ width: 30px; text-align: right; font-weight: 700; font-size: .9rem; }}
  .plugin-section {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    margin-bottom: 20px; overflow: hidden; }}
  .plugin-title {{ padding: 16px 24px; cursor: pointer; font-size: 1.05rem; font-weight: 600;
    background: #fafbfc; border-bottom: 1px solid var(--border); user-select: none;
    display: flex; justify-content: space-between; align-items: center; }}
  .plugin-title:hover {{ background: #f0f2f5; }}
  .plugin-count {{ font-size: .8rem; background: #e8eaf0; padding: 2px 10px; border-radius: 20px;
    color: var(--muted); font-weight: 500; }}
  .plugin-body {{ padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }}
  .plugin-body.hidden {{ display: none; }}
  .finding-card {{ border-radius: 8px; padding: 16px 20px; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
  .badge {{ color: #fff; font-size: .72rem; font-weight: 700; padding: 2px 8px;
    border-radius: 4px; text-transform: uppercase; letter-spacing: .05em; white-space: nowrap; }}
  .finding-title {{ font-size: .95rem; font-weight: 600; }}
  .finding-desc {{ font-size: .88rem; line-height: 1.6; color: #444; margin-bottom: 8px; }}
  .finding-file {{ font-size: .82rem; color: var(--muted); margin-bottom: 6px; }}
  .also-detected {{ font-size: .8rem; color: #8e44ad; background: #f3eafb; border: 1px solid #e1cdf0;
    padding: 2px 10px; border-radius: 6px; display: inline-block; margin: 0 0 8px; font-weight: 500; }}
  .finding-rec {{ font-size: .85rem; color: #2c7c5c; margin: 8px 0; }}
  .evidence {{ margin-top: 8px; background: #1e1e2e; border-radius: 6px; padding: 10px 14px; }}
  .evidence strong {{ color: #a0a0c0; font-size: .78rem; display: block; margin-bottom: 4px; }}
  .evidence pre {{ color: #cdd6f4; font-size: .82rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .tags {{ margin-top: 8px; display: flex; flex-wrap: wrap; gap: 4px; }}
  .tag {{ background: #edf2f7; color: #718096; font-size: .72rem; padding: 1px 8px; border-radius: 20px; }}
  .proj-info {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px 28px; margin-bottom: 28px; }}
  .proj-info h3 {{ color: var(--muted); font-size: .85rem; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 14px; }}
  .proj-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }}
  .proj-item {{ min-width: 0; }}  /* allow the cell to shrink so long values wrap, not overflow */
  .proj-item strong {{ display: block; font-size: .75rem; color: var(--muted); margin-bottom: 2px; }}
  .proj-item span {{ font-size: .9rem; font-weight: 500; display: block;
    overflow-wrap: anywhere; word-break: break-word; }}
  .section-summary {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 20px 28px; margin-bottom: 28px; }}
  .section-summary h3 {{ color: var(--muted); font-size: .85rem; text-transform: uppercase; letter-spacing: .05em; margin-bottom: 14px; }}
  .sec-table-wrap {{ overflow-x: auto; }}
  .sec-table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  .sec-table th, .sec-table td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); }}
  .sec-table th {{ color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; text-align: left; }}
  .sec-table th.num, .sec-table td.num {{ text-align: center; }}
  .sec-table .sec-name {{ font-weight: 600; padding-left: 12px; white-space: nowrap; }}
  .sec-table .zero {{ color: #cfd6dd; }}
  .sec-table .sec-total {{ font-weight: 700; }}
  .sec-table tbody tr.sec-row {{ cursor: pointer; }}
  .sec-table tbody tr.sec-row:hover {{ background: #f0f2f5; }}
  .sec-table .jump {{ color: #b0b7c0; font-size: .8rem; opacity: 0; transition: opacity .15s; }}
  .sec-table tbody tr.sec-row:hover .jump {{ opacity: 1; }}
  .plugin-section {{ scroll-margin-top: 12px; transition: box-shadow .3s ease; }}
  .plugin-section.flash {{ box-shadow: 0 0 0 3px rgba(142, 68, 173, .55); }}
  .subgroup {{ border: 1px solid #e9ecef; border-radius: 8px; margin-top: 10px; }}
  .subgroup .plugin-title {{ background: #f8f9fa; font-size: .95rem; }}
  footer {{ text-align: center; color: var(--muted); font-size: .8rem; margin-top: 40px; }}
  @media (max-width: 600px) {{
    .score-row {{ flex-direction: column; }}
    header {{ padding: 24px 20px; }}
  }}
</style>
</head>
<body>
<header>
  <h1>🔒 Security Scan Report</h1>
  <div class="meta">
    <strong>Project:</strong> {_esc(project_info.get("project_name", "Unknown"))}&nbsp;&nbsp;
    <strong>Generated:</strong> {_esc(generated_at)}<br>
    <strong>Repo:</strong> {_esc(project_info.get("git_remote", "N/A"))}&nbsp;&nbsp;
    <strong>Branch:</strong> {_esc(project_info.get("git_branch", "N/A"))}<br>
    <strong>Languages:</strong> {_esc(", ".join(project_info.get("languages", ["N/A"])))}&nbsp;&nbsp;
    <strong>Framework:</strong> {_esc(project_info.get("framework", "N/A"))}&nbsp;&nbsp;
    <strong>Environment:</strong> {_esc(project_info.get("environment", "N/A"))}
  </div>
</header>

<div class="container">
  <div class="score-row">
    <div class="score-card">
      <div class="score-num">{score}</div>
      <div class="score-label">Security Score / 100{f' &middot; Grade {_esc(grade)}' if grade else ''}</div>
    </div>
    <div class="summary-card">
      <h3>Findings by Severity</h3>
      {''.join(summary_bars)}
    </div>
  </div>

  <div class="proj-info">
    <h3>Project Information</h3>
    <div class="proj-grid">
      <div class="proj-item"><strong>Project Name</strong><span>{_esc(project_info.get("project_name", "N/A"))}</span></div>
      <div class="proj-item"><strong>Environment</strong><span>{_esc(project_info.get("environment", "N/A"))}</span></div>
      <div class="proj-item"><strong>Scanned Path</strong><span>{_esc(project_info.get("scan_path", "N/A"))}</span></div>
      <div class="proj-item"><strong>Languages</strong><span>{_esc(", ".join(project_info.get("languages", [])))}</span></div>
      <div class="proj-item"><strong>Framework</strong><span>{_esc(project_info.get("framework", "N/A"))}</span></div>
      <div class="proj-item"><strong>Git Branch</strong><span>{_esc(project_info.get("git_branch", "N/A"))}</span></div>
      <div class="proj-item"><strong>Last Commit</strong><span>{_esc(project_info.get("git_last_commit", "N/A"))}</span></div>
      <div class="proj-item"><strong>Total Files Scanned</strong><span>{_esc(str(project_info.get("files_scanned", "N/A")))}</span></div>
    </div>
  </div>

  {section_summary_html}

  {''.join(findings_html_parts)}
</div>

<footer>
  Generated by Security Scanner &bull; {_esc(generated_at)} &bull; {total} finding(s)
</footer>

<script>
function toggleSection(el) {{
  const body = el.nextElementSibling;
  body.classList.toggle('hidden');
  el.textContent = el.textContent.startsWith('▾')
    ? el.textContent.replace('▾', '▸')
    : el.textContent.replace('▸', '▾');
}}
function goToSection(id) {{
  const el = document.getElementById(id);
  if (!el) return;
  const title = el.querySelector('.plugin-title');
  const body = el.querySelector('.plugin-body');
  // Expand the target section if it was collapsed (e.g. auto-collapsed INFO-only).
  if (title && body && body.classList.contains('hidden')) toggleSection(title);
  el.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
  el.classList.add('flash');
  setTimeout(function() {{ el.classList.remove('flash'); }}, 1500);
}}
// Auto-collapse INFO sections
document.querySelectorAll('.plugin-title').forEach(function(el) {{
  const findings = el.nextElementSibling.querySelectorAll('.finding-card');
  let onlyInfo = true;
  findings.forEach(function(f) {{
    if (!f.querySelector('.badge[style*="#7f8c8d"]')) onlyInfo = false;
  }});
  if (onlyInfo && findings.length > 0) toggleSection(el);
}});
</script>
</body>
</html>"""
