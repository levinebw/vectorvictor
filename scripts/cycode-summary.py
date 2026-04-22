#!/usr/bin/env python3
"""Generate a short Markdown summary of a Cycode JSON scan result.

The output is used with `##vso[task.uploadsummary]` so the summary appears
as a tab on the Azure Pipelines build summary page.

Usage:
  cycode -o json scan -t sast path ./src > cycode.json
  cycode-summary.py cycode.json > cycode-summary.md
"""
from __future__ import annotations

import json
import sys


def extract_detections(data):
    detections = []
    if isinstance(data, dict):
        for block in data.get("scan_results", []) or []:
            detections.extend(block.get("detections", []) or [])
        detections.extend(data.get("detections", []) or [])
    elif isinstance(data, list):
        detections = list(data)
    return detections


def main(src: str) -> int:
    with open(src) as f:
        data = json.load(f)

    detections = extract_detections(data)
    counts: dict[str, int] = {}
    for d in detections:
        sev = d.get("severity") or "Unknown"
        counts[sev] = counts.get(sev, 0) + 1

    lines = []
    lines.append("## Cycode Scan Summary")
    lines.append("")
    lines.append(f"**Total findings:** {len(detections)}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]:
        if counts.get(sev):
            lines.append(f"| {sev} | {counts[sev]} |")
    lines.append("")

    if detections:
        lines.append("### Top findings")
        for d in detections[:10]:
            dd = d.get("detection_details") or {}
            path = dd.get("file_path") or d.get("file_path") or "?"
            line = dd.get("line") or d.get("line") or ""
            msg = (d.get("message") or d.get("detection_rule_id") or "")[:120]
            loc = f"`{path}:{line}`" if line else f"`{path}`"
            lines.append(f"- **[{d.get('severity', '?')}]** {msg} — {loc}")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: cycode-summary.py <input.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
