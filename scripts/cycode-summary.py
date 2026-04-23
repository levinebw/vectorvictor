#!/usr/bin/env python3
"""Generate Markdown + HTML + CSV reports from Cycode CLI JSON scan output.

Produces up to three output formats from a single `cycode -o json scan` file:

  * Markdown  — short summary suitable for Azure Pipelines' `task.uploadsummary`.
                Written to stdout (or --md FILE).
  * HTML      — rich, self-contained interactive report (filterable, expandable
                descriptions, severity badges). Written to --html FILE.
  * CSV       — flat, Excel-friendly export of every finding with the 7 columns
                requested by customers. Written to --csv FILE.

Usage:
  cycode-summary.py cycode.json                         # Markdown to stdout
  cycode-summary.py cycode.json \
      --md  cycode-summary.md \
      --html cycode-report.html \
      --csv cycode-report.csv

Column mapping (HTML + CSV):
  Issue Name        — detection_details.policy_display_name
  Issue Description — detection_details.description (falls back to top-level message)
  Where             — detection_details.line / start_position
  File              — detection_details.file_path  (agent workspace prefix stripped)
  Metadata          — severity, type, CWE, OWASP, category, language(s)
  Mitigation        — detection_details.remediation_guidelines (Markdown from platform)
  Ref URL           — <console-base>/policies/<detection_rule_id>
                       (override base with CYCODE_CONSOLE_URL env var or --console-url)
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
from typing import Any

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]

SEVERITY_COLOR = {
    "Critical": "#b71c1c",
    "High":     "#e65100",
    "Medium":   "#f9a825",
    "Low":      "#1565c0",
    "Info":     "#546e7a",
    "Unknown":  "#37474f",
}


def extract_detections(data: Any) -> list[dict]:
    detections: list[dict] = []
    if isinstance(data, dict):
        for block in data.get("scan_results") or []:
            detections.extend(block.get("detections") or [])
        detections.extend(data.get("detections") or [])
    elif isinstance(data, list):
        detections = list(data)
    return detections


def normalize_file_path(path: str) -> str:
    """Strip ADO / GitHub Actions agent workspace prefixes for readability."""
    if not path:
        return ""
    # ADO self-hosted / hosted: /_work/<n>/s/<repo-relative>
    m = re.search(r"/_work/\d+/s/(.+)$", path)
    if m:
        return m.group(1)
    # GitHub Actions: /home/runner/work/<repo>/<repo>/<repo-relative>
    m = re.search(r"/runner/work/[^/]+/[^/]+/(.+)$", path)
    if m:
        return m.group(1)
    return path.lstrip("/")


def row_from_detection(d: dict) -> dict:
    dd = d.get("detection_details") or {}
    cwe = dd.get("cwe") or []
    owasp = dd.get("owasp") or []
    langs = dd.get("languages") or []
    metadata_parts = []
    if cwe:
        metadata_parts.append("CWE: " + "; ".join(cwe))
    if owasp:
        metadata_parts.append("OWASP: " + "; ".join(owasp))
    if dd.get("category"):
        metadata_parts.append(f"Category: {dd['category']}")
    if langs:
        metadata_parts.append("Languages: " + ", ".join(langs))
    return {
        "severity":         d.get("severity") or "Unknown",
        "type":             d.get("type") or "?",
        "issue_name":       dd.get("policy_display_name") or d.get("detection_rule_id") or "Unnamed finding",
        "description":      (dd.get("description") or d.get("message") or "").strip(),
        "file":             normalize_file_path(dd.get("file_path") or d.get("file_path") or ""),
        "line":             dd.get("line") or d.get("line") or "",
        "metadata":         " | ".join(metadata_parts),
        "cwe":              "; ".join(cwe),
        "owasp":            "; ".join(owasp),
        "category":         dd.get("category") or "",
        "languages":        ", ".join(langs),
        "remediation":      (dd.get("remediation_guidelines") or dd.get("custom_remediation_guidelines") or "").strip(),
        "detection_rule_id": dd.get("detection_rule_id") or "",
        "policy_id":        dd.get("policy_id") or "",
        "id":               d.get("id") or "",
    }


def console_url(row: dict, base_url: str) -> str:
    base = base_url.rstrip("/")
    rule_id = row.get("detection_rule_id") or row.get("policy_id")
    if rule_id:
        return f"{base}/policies/{rule_id}"
    return base


def count_by_severity(rows: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def severity_sort_key(row: dict) -> tuple:
    try:
        idx = SEVERITY_ORDER.index(row["severity"])
    except ValueError:
        idx = len(SEVERITY_ORDER)
    return (idx, row["type"], row["file"], row["line"] or 0)


# ----------------------------- Markdown -----------------------------------

def render_markdown(rows: list[dict], base_url: str, artifact_hint: str = "") -> str:
    counts = count_by_severity(rows)
    lines: list[str] = []
    lines.append("## Cycode Scan Summary")
    lines.append("")
    lines.append(f"**Total findings:** {len(rows)}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    if artifact_hint:
        lines.append(f"> Full HTML + CSV reports are published as the **{artifact_hint}** artifact on this build.")
        lines.append("")

    if rows:
        lines.append("### Top findings (by severity)")
        lines.append("")
        for r in rows[:15]:
            loc = f"`{r['file']}:{r['line']}`" if r["line"] else f"`{r['file']}`"
            url = console_url(r, base_url)
            desc = r["description"][:200]
            lines.append(
                f"- **[{r['severity']}]** {r['issue_name']} — {loc}  \n"
                f"  {desc}{'...' if len(r['description']) > 200 else ''}  \n"
                f"  [↗ Console]({url})"
            )
        lines.append("")
    return "\n".join(lines)


# ------------------------------- HTML -------------------------------------

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cycode Scan Report</title>
<style>
  :root {{ --bg:#f7f8fa; --fg:#212121; --muted:#546e7a; --card:#fff; --border:#e0e3e7; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px; line-height: 1.45;
  }}
  h1 {{ margin: 0 0 8px; font-size: 22px; }}
  .meta {{ color: var(--muted); margin-bottom: 20px; }}
  .summary-grid {{
    display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px;
  }}
  .summary-card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 12px 16px; min-width: 110px;
  }}
  .summary-card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.4px; }}
  .summary-card .value {{ font-size: 22px; font-weight: 600; margin-top: 2px; }}
  .controls {{
    display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; align-items: center;
  }}
  .controls input, .controls select {{
    padding: 7px 10px; border: 1px solid var(--border); border-radius: 6px;
    font-size: 13px; background: #fff;
  }}
  .controls input {{ flex: 1; min-width: 200px; }}
  table {{
    width: 100%; border-collapse: collapse; background: var(--card);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
  }}
  thead th {{
    text-align: left; padding: 10px 12px; font-size: 12px;
    text-transform: uppercase; letter-spacing: 0.4px; color: var(--muted);
    background: #eceff1; border-bottom: 1px solid var(--border);
  }}
  tbody td {{
    padding: 12px; vertical-align: top; border-bottom: 1px solid var(--border);
  }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr.hidden {{ display: none; }}
  .sev {{
    display: inline-block; padding: 2px 10px; border-radius: 10px;
    color: #fff; font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.4px; white-space: nowrap;
  }}
  .type-badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    background: #eceff1; color: #37474f; font-size: 11px; font-weight: 500;
  }}
  .file {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; word-break: break-all; }}
  .line {{ color: var(--muted); }}
  .meta-col {{ color: var(--muted); font-size: 12.5px; }}
  details {{ margin-top: 6px; }}
  details summary {{
    cursor: pointer; color: #1565c0; font-size: 12.5px; user-select: none;
    list-style: none;
  }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary::before {{ content: "▸ "; color: #1565c0; }}
  details[open] summary::before {{ content: "▾ "; }}
  details .content {{
    margin-top: 6px; padding: 10px 12px; background: #fafbfc;
    border-left: 3px solid #1565c0; border-radius: 4px;
    font-size: 13px; white-space: pre-wrap;
  }}
  .console-link {{
    display: inline-block; padding: 4px 10px; background: #1565c0; color: #fff;
    border-radius: 4px; text-decoration: none; font-size: 12px; white-space: nowrap;
  }}
  .console-link:hover {{ background: #0d47a1; }}
  .empty {{ text-align: center; padding: 40px; color: var(--muted); }}
  footer {{ margin-top: 20px; color: var(--muted); font-size: 12px; }}
  footer a {{ color: #1565c0; }}
</style>
</head>
<body>
<h1>Cycode Scan Report</h1>
<div class="meta">Generated {generated_at} &middot; {total} finding{plural} across {scan_types}</div>

<div class="summary-grid">
  {summary_cards}
</div>

<div class="controls">
  <input id="search" type="search" placeholder="Filter by file, issue name, description, CWE..." autofocus>
  <select id="severity-filter">
    <option value="">All severities</option>
    {severity_options}
  </select>
  <select id="type-filter">
    <option value="">All types</option>
    {type_options}
  </select>
  <span id="shown-count" style="color: var(--muted); font-size: 12px;"></span>
</div>

<table id="findings">
  <thead>
    <tr>
      <th style="width:90px;">Severity</th>
      <th>Issue Name</th>
      <th>Description &amp; Mitigation</th>
      <th style="width:260px;">File &amp; Line</th>
      <th style="width:220px;">Metadata</th>
      <th style="width:110px;">Console</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>

<footer>
  Report generated from <code>cycode -o json scan</code> output.
  Console base: <a href="{console_base}">{console_base}</a>.
  For full platform-side tracking (triaged state, reachability, custom policies),
  connect this repository to Cycode via the SCM integration.
</footer>

<script>
(function() {{
  var rows = document.querySelectorAll('#findings tbody tr');
  var search = document.getElementById('search');
  var sevFilter = document.getElementById('severity-filter');
  var typeFilter = document.getElementById('type-filter');
  var shownCount = document.getElementById('shown-count');

  function apply() {{
    var q = search.value.trim().toLowerCase();
    var sev = sevFilter.value;
    var typ = typeFilter.value;
    var shown = 0;
    rows.forEach(function(tr) {{
      var haystack = tr.getAttribute('data-search') || '';
      var rowSev = tr.getAttribute('data-severity') || '';
      var rowType = tr.getAttribute('data-type') || '';
      var match =
        (!q || haystack.indexOf(q) !== -1) &&
        (!sev || rowSev === sev) &&
        (!typ || rowType === typ);
      tr.classList.toggle('hidden', !match);
      if (match) shown++;
    }});
    shownCount.textContent = 'Showing ' + shown + ' of ' + rows.length;
  }}

  search.addEventListener('input', apply);
  sevFilter.addEventListener('change', apply);
  typeFilter.addEventListener('change', apply);
  apply();
}})();
</script>
</body>
</html>
"""


def render_html(rows: list[dict], base_url: str, scan_types: list[str]) -> str:
    import datetime

    counts = count_by_severity(rows)
    present_sevs = [s for s in SEVERITY_ORDER if counts.get(s)]
    present_types = sorted({r["type"] for r in rows if r.get("type")})

    summary_cards = ['<div class="summary-card"><div class="label">Total</div>'
                     f'<div class="value">{len(rows)}</div></div>']
    for sev in present_sevs:
        color = SEVERITY_COLOR.get(sev, "#000")
        summary_cards.append(
            f'<div class="summary-card"><div class="label">{html.escape(sev)}</div>'
            f'<div class="value" style="color:{color};">{counts[sev]}</div></div>'
        )

    severity_options = "\n    ".join(
        f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in present_sevs
    )
    type_options = "\n    ".join(
        f'<option value="{html.escape(t)}">{html.escape(t)}</option>' for t in present_types
    )

    row_html_parts: list[str] = []
    for r in rows:
        sev_color = SEVERITY_COLOR.get(r["severity"], "#000")
        url = console_url(r, base_url)
        location = html.escape(r["file"] or "unknown")
        line_html = f'<div class="line">Line {html.escape(str(r["line"]))}</div>' if r["line"] else ""
        meta_parts = []
        if r["cwe"]: meta_parts.append(f"<div><strong>CWE:</strong> {html.escape(r['cwe'])}</div>")
        if r["owasp"]: meta_parts.append(f"<div><strong>OWASP:</strong> {html.escape(r['owasp'])}</div>")
        if r["category"]: meta_parts.append(f"<div><strong>Category:</strong> {html.escape(r['category'])}</div>")
        if r["languages"]: meta_parts.append(f"<div><strong>Language:</strong> {html.escape(r['languages'])}</div>")
        metadata_html = "".join(meta_parts) or '<span style="color:var(--muted);">—</span>'

        # Description + Mitigation combined in one cell with expandable <details>
        description_full = r["description"]
        remediation = r["remediation"]
        desc_short = description_full[:180] + ("..." if len(description_full) > 180 else "")
        desc_cell_parts = [f'<div>{html.escape(desc_short)}</div>']
        if description_full and len(description_full) > 180:
            desc_cell_parts.append(
                f'<details><summary>Full description</summary>'
                f'<div class="content">{html.escape(description_full)}</div></details>'
            )
        if remediation:
            desc_cell_parts.append(
                f'<details><summary>Mitigation guidance</summary>'
                f'<div class="content">{html.escape(remediation)}</div></details>'
            )

        # Build a searchable haystack for client-side filtering
        haystack = " ".join([
            r["severity"], r["type"], r["issue_name"], r["description"],
            r["file"], str(r["line"]), r["cwe"], r["owasp"],
            r["category"], r["languages"],
        ]).lower()

        row_html_parts.append(
            f'<tr data-severity="{html.escape(r["severity"])}" '
            f'data-type="{html.escape(r["type"])}" '
            f'data-search="{html.escape(haystack)}">'
            f'<td><span class="sev" style="background:{sev_color};">{html.escape(r["severity"])}</span>'
            f'<div style="margin-top:6px;"><span class="type-badge">{html.escape(r["type"])}</span></div></td>'
            f'<td><strong>{html.escape(r["issue_name"])}</strong></td>'
            f'<td>{"".join(desc_cell_parts)}</td>'
            f'<td><div class="file">{location}</div>{line_html}</td>'
            f'<td class="meta-col">{metadata_html}</td>'
            f'<td><a class="console-link" href="{html.escape(url)}" target="_blank" rel="noopener">View ↗</a></td>'
            f'</tr>'
        )

    if not row_html_parts:
        row_html_parts.append('<tr><td colspan="6" class="empty">No findings.</td></tr>')

    return HTML_TEMPLATE.format(
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(rows),
        plural="" if len(rows) == 1 else "s",
        scan_types=", ".join(scan_types) if scan_types else "scan",
        summary_cards="\n  ".join(summary_cards),
        severity_options=severity_options,
        type_options=type_options,
        rows="\n    ".join(row_html_parts),
        console_base=html.escape(base_url),
    )


# -------------------------------- CSV -------------------------------------

CSV_COLUMNS = [
    "severity",
    "type",
    "issue_name",
    "description",
    "file",
    "line",
    "cwe",
    "owasp",
    "category",
    "languages",
    "mitigation",
    "console_url",
    "detection_rule_id",
    "policy_id",
    "detection_id",
]


def write_csv(rows: list[dict], path: str, base_url: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "Severity", "Type", "Issue Name", "Issue Description",
            "File", "Line", "CWE", "OWASP", "Category", "Languages",
            "Mitigation", "Console URL",
            "Detection Rule ID", "Policy ID", "Detection ID",
        ])
        for r in rows:
            writer.writerow([
                r["severity"], r["type"], r["issue_name"], r["description"],
                r["file"], r["line"], r["cwe"], r["owasp"], r["category"], r["languages"],
                r["remediation"], console_url(r, base_url),
                r["detection_rule_id"], r["policy_id"], r["id"],
            ])


# ------------------------------- main -------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_json")
    parser.add_argument("--md", help="Write Markdown here (default: stdout)")
    parser.add_argument("--html", help="Write HTML report here")
    parser.add_argument("--csv", help="Write CSV export here")
    parser.add_argument(
        "--console-url",
        default=os.environ.get("CYCODE_CONSOLE_URL", "https://app.cycode.com"),
        help="Base URL of the Cycode console (default: $CYCODE_CONSOLE_URL or https://app.cycode.com)",
    )
    parser.add_argument(
        "--artifact-hint",
        default=os.environ.get("CYCODE_ARTIFACT_NAME", "cycode-report"),
        help="Artifact name to reference in the Markdown summary (default: $CYCODE_ARTIFACT_NAME or cycode-report)",
    )
    args = parser.parse_args()

    with open(args.input_json) as f:
        data = json.load(f)

    detections = extract_detections(data)
    rows = [row_from_detection(d) for d in detections]
    rows.sort(key=severity_sort_key)

    scan_types = sorted({r["type"] for r in rows if r.get("type")})

    md = render_markdown(rows, args.console_url, args.artifact_hint if (args.html or args.csv) else "")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(rows, args.console_url, scan_types))

    if args.csv:
        write_csv(rows, args.csv, args.console_url)

    return 0


if __name__ == "__main__":
    sys.exit(main())
