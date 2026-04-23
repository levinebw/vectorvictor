#!/usr/bin/env python3
"""Convert Cycode CLI JSON output (cycode -o json scan ...) to JUnit XML.

Azure Pipelines renders JUnit via PublishTestResults@2 on the Tests tab.
Each Cycode finding becomes a failed testcase so reviewers can drill into
individual violations by severity and file.

Usage:
  cycode -o json scan -t sast path ./src > cycode.json
  cycode-json-to-junit.py cycode.json cycode-junit.xml
"""
from __future__ import annotations

import json
import sys
from xml.sax.saxutils import escape, quoteattr


def extract_detections(data):
    detections = []
    if isinstance(data, dict):
        for block in data.get("scan_results", []) or []:
            detections.extend(block.get("detections", []) or [])
        detections.extend(data.get("detections", []) or [])
    elif isinstance(data, list):
        detections = list(data)
    return detections


def detection_fields(d):
    dd = d.get("detection_details") or {}
    severity = d.get("severity") or "UNKNOWN"
    path = dd.get("file_path") or d.get("file_path") or "unknown"
    line = dd.get("line") or d.get("line") or ""
    policy = (
        d.get("policy_display_name")
        or d.get("detection_rule_id")
        or d.get("policy_id")
        or "Cycode"
    )
    message = d.get("message") or policy
    return severity, policy, path, line, message


def main(src: str, dst: str) -> int:
    with open(src) as f:
        data = json.load(f)

    detections = extract_detections(data)
    total = len(detections)

    out = ['<?xml version="1.0" encoding="UTF-8"?>']
    out.append(
        f'<testsuite name="Cycode" tests="{total}" '
        f'failures="{total}" errors="0" skipped="0">'
    )

    for d in detections:
        severity, policy, path, line, message = detection_fields(d)
        classname = f"{severity}.{policy}"
        name = f"{path}:{line}" if line else path
        detail = json.dumps(d, indent=2, default=str)
        cdata = detail.replace("]]>", "]]]]><![CDATA[>")
        # Use quoteattr (returns the value wrapped in quotes with ", &, <, >
        # escaped). Plain escape() doesn't handle " — any finding message
        # containing a double quote breaks PublishTestResults@2 parsing.
        out.append(f'  <testcase classname={quoteattr(classname)} name={quoteattr(name)}>')
        out.append(
            f'    <failure type={quoteattr(severity)} '
            f'message={quoteattr(str(message)[:200])}><![CDATA[\n{cdata}\n]]></failure>'
        )
        out.append("  </testcase>")

    out.append("</testsuite>")

    with open(dst, "w") as f:
        f.write("\n".join(out))

    print(f"Wrote {total} findings to {dst}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: cycode-json-to-junit.py <input.json> <output.xml>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
