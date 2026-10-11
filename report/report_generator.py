import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from config import Config
from database.db import query

_env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "..", "templates")))


def generate_html_report(scan_id: int) -> str:
    scan = query("SELECT * FROM scans WHERE id=%s", (scan_id,))[0]
    ports = query("SELECT * FROM scan_ports WHERE scan_id=%s ORDER BY port", (scan_id,))
    vulns = query("SELECT * FROM vulnerabilities WHERE scan_id=%s ORDER BY cvss_score DESC", (scan_id,))
    web_findings = query("SELECT * FROM web_findings WHERE scan_id=%s ORDER BY FIELD(severity,'HIGH','MEDIUM','LOW','INFO','UNKNOWN')", (scan_id,))

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    for v in vulns:
        severity_counts[v["severity"] or "UNKNOWN"] = severity_counts.get(v["severity"] or "UNKNOWN", 0) + 1
    for f in web_findings:
        severity_counts[f["severity"] or "UNKNOWN"] = severity_counts.get(f["severity"] or "UNKNOWN", 0) + 1

    template = _env.get_template("report.html")
    html = template.render(
        scan=scan, ports=ports, vulns=vulns, web_findings=web_findings,
        severity_counts=severity_counts, generated_at=datetime.utcnow(),
    )

    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    filename = f"report_scan{scan_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.html"
    path = os.path.join(Config.REPORTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)

    query(
        "INSERT INTO reports (scan_id, file_path, format) VALUES (%s,%s,'html')",
        (scan_id, path), fetch=False,
    )
    return path
