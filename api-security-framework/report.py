import os
#!/usr/bin/env python3
"""
Report generator — produces a clean HTML dashboard from scan findings.
"""

from datetime import datetime


SEVERITY_COLOR = {
    "High":          "#e53e3e",
    "Medium":        "#dd6b20",
    "Low":           "#d69e2e",
    "Informational": "#3182ce",
}

SEVERITY_BG = {
    "High":          "#fff5f5",
    "Medium":        "#fffaf0",
    "Low":           "#fffff0",
    "Informational": "#ebf8ff",
}


def _badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "#718096")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 10px;'
        f'border-radius:12px;font-size:12px;font-weight:600;">{severity}</span>'
    )


def _finding_card(finding: dict, index: int) -> str:
    severity = finding.get("risk", finding.get("Risk", "Informational"))
    name     = finding.get("name", finding.get("alert", "Unknown"))
    desc     = finding.get("description", finding.get("desc", "No description available."))
    solution = finding.get("solution", finding.get("solution", ""))
    owasp    = finding.get("owasp", "Uncategorized")
    url      = finding.get("url", "")
    urls     = finding.get("urls", [url] if url else [])
    evidence = finding.get("evidence", "")
    bg       = SEVERITY_BG.get(severity, "#f7fafc")

    urls_html = ""
    if urls:
        urls_html = "<br>".join(
            f'<code style="font-size:12px;background:#edf2f7;padding:2px 6px;border-radius:4px;">{u}</code>'
            for u in urls[:3]
        )

    evidence_html = ""
    if evidence:
        evidence_html = f"""
        <div style="margin-top:8px;">
          <strong style="font-size:13px;">Evidence:</strong><br>
          <code style="font-size:12px;background:#edf2f7;padding:4px 8px;border-radius:4px;display:block;margin-top:4px;word-break:break-all;">{evidence[:300]}</code>
        </div>"""

    solution_html = ""
    if solution:
        solution_html = f"""
        <div style="margin-top:8px;padding:8px 12px;background:#f0fff4;border-left:3px solid #38a169;border-radius:0 4px 4px 0;">
          <strong style="font-size:13px;color:#276749;">Remediation:</strong>
          <p style="margin:4px 0 0;font-size:13px;color:#276749;">{solution}</p>
        </div>"""

    return f"""
    <div style="background:{bg};border:1px solid #e2e8f0;border-left:4px solid {SEVERITY_COLOR.get(severity,'#718096')};
                border-radius:8px;padding:16px 20px;margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <strong style="font-size:15px;">#{index + 1} — {name}</strong>
        {_badge(severity)}
      </div>
      <div style="margin-bottom:6px;">
        <span style="background:#e2e8f0;color:#4a5568;padding:2px 8px;border-radius:10px;font-size:12px;">{owasp}</span>
      </div>
      <p style="font-size:13px;color:#4a5568;margin:8px 0;">{desc[:400]}</p>
      {f'<div style="margin-top:8px;">{urls_html}</div>' if urls_html else ''}
      {evidence_html}
      {solution_html}
    </div>"""


def generate_report(
    zap_findings: list,
    custom_findings: list,
    target: str,
    output_path: str,
) -> None:
    all_findings = zap_findings + custom_findings
    total  = len(all_findings)
    high   = sum(1 for f in zap_findings if f.get("risk","").lower() == "high")
    medium = sum(1 for f in zap_findings if f.get("risk","").lower() == "medium")
    low    = sum(1 for f in zap_findings if f.get("risk","").lower() == "low")
    info   = sum(1 for f in zap_findings if f.get("risk","").lower() == "informational")

    scan_date = datetime.now().strftime("%B %d, %Y at %H:%M")

    # Stat cards
    def stat_card(label, count, color):
        return f"""
        <div style="background:#fff;border:1px solid #e2e8f0;border-top:4px solid {color};
                    border-radius:8px;padding:20px;text-align:center;min-width:110px;">
          <div style="font-size:36px;font-weight:700;color:{color};">{count}</div>
          <div style="font-size:13px;color:#718096;margin-top:4px;">{label}</div>
        </div>"""

    cards = (
        stat_card("Total", total, "#667eea") +
        stat_card("High", high, "#e53e3e") +
        stat_card("Medium", medium, "#dd6b20") +
        stat_card("Low", low, "#d69e2e") +
        stat_card("Info", info, "#3182ce")
    )

    # OWASP breakdown
    owasp_counts = {}
    for f in zap_findings:
        cat = f.get("owasp", "Uncategorized")
        owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

    owasp_rows = "".join(
        f"""<tr>
          <td style="padding:8px 12px;font-size:13px;">{cat}</td>
          <td style="padding:8px 12px;font-size:13px;font-weight:600;">{count}</td>
        </tr>"""
        for cat, count in sorted(owasp_counts.items(), key=lambda x: -x[1])
    )

    # Finding cards grouped by severity
    def section(label, sev, findings):
        items = [f for f in findings if f.get("risk", f.get("Risk", "")) == sev]
        if not items:
            return ""
        cards_html = "".join(_finding_card(f, i) for i, f in enumerate(items))
        color = SEVERITY_COLOR.get(sev, "#718096")
        return f"""
        <h3 style="color:{color};border-bottom:2px solid {color};padding-bottom:6px;margin:28px 0 16px;">
          {label} Severity ({len(items)})
        </h3>
        {cards_html}"""

    findings_html = (
        section("High",   "High",          zap_findings) +
        section("Medium", "Medium",         zap_findings) +
        section("Low",    "Low",            zap_findings) +
        section("Info",   "Informational",  zap_findings)
    ) or '<p style="color:#718096;text-align:center;padding:40px;">No findings to display.</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Security Scan Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f7fafc; color: #2d3748; }}
    .container {{ max-width: 960px; margin: 0 auto; padding: 32px 24px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    tr:nth-child(even) {{ background: #f7fafc; }}
    th {{ background: #edf2f7; padding: 10px 12px; text-align: left; font-size: 13px; }}
  </style>
</head>
<body>
  <div style="background:linear-gradient(135deg,#1a365d,#2b6cb0);padding:32px 24px;color:#fff;">
    <div class="container" style="padding:0;">
      <h1 style="font-size:26px;font-weight:700;">API Security Scan Report</h1>
      <p style="margin-top:8px;opacity:0.85;">Target: <strong>{target}</strong></p>
      <p style="margin-top:4px;opacity:0.7;font-size:13px;">Generated: {scan_date}</p>
    </div>
  </div>

  <div class="container">
    <!-- Summary cards -->
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin:28px 0;">
      {cards}
    </div>

    <!-- OWASP breakdown -->
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;margin-bottom:28px;">
      <h3 style="font-size:16px;margin-bottom:12px;">OWASP API Top 10 Breakdown</h3>
      <table>
        <thead><tr><th>Category</th><th>Count</th></tr></thead>
        <tbody>{owasp_rows}</tbody>
      </table>
    </div>

    <!-- Findings -->
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:24px;">
      <h3 style="font-size:16px;margin-bottom:4px;">Findings Detail</h3>
      <p style="font-size:13px;color:#718096;margin-bottom:20px;">
        {total} total findings across {len(owasp_counts)} OWASP categories
      </p>
      {findings_html}
    </div>

    <p style="text-align:center;font-size:12px;color:#a0aec0;margin-top:24px;">
      Generated by Secure API Testing Framework &nbsp;|&nbsp; OWASP API Top 10 (2023)
    </p>
  </div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML dashboard saved → {output_path}")
