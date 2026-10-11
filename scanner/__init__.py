"""Orchestrates a full scan: ports -> services -> CVE matches -> web checks,
persisting every stage to MySQL as it goes."""
from datetime import datetime
from database.db import query
from scanner.port_scanner import scan_target
from scanner.vuln_lookup import lookup_cves
from scanner.web_scanner import run_web_scan
from scanner.authorization import require_authorization, NotAuthorizedError


def run_full_scan(scan_id: int, target: str, scan_type: str, port_range: str):
    try:
        require_authorization(target)
        query("UPDATE scans SET status='running' WHERE id=%s", (scan_id,), fetch=False)

        if scan_type in ("port", "full"):
            ports, engine = scan_target(target, port_range)
            for p in ports:
                port_row_id = query(
                    """INSERT INTO scan_ports
                       (scan_id, port, protocol, state, service_name, product, version, banner)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (scan_id, p["port"], p["protocol"], p["state"], p["service_name"],
                     p["product"], p["version"], p["banner"]),
                    fetch=False,
                )
                if p["product"]:
                    cves = lookup_cves(p["product"], p["version"])
                    for c in cves:
                        query(
                            """INSERT INTO vulnerabilities
                               (scan_id, scan_port_id, cve_id, severity, cvss_score, description, reference_url)
                               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                            (scan_id, port_row_id, c["cve_id"], c["severity"], c["cvss_score"],
                             c["description"], c["reference_url"]),
                            fetch=False,
                        )

        if scan_type in ("web", "full"):
            web_findings = run_web_scan(target)
            for f in web_findings:
                query(
                    """INSERT INTO web_findings (scan_id, category, finding, severity, detail)
                       VALUES (%s,%s,%s,%s,%s)""",
                    (scan_id, f["category"], f["finding"], f["severity"], f["detail"]),
                    fetch=False,
                )

        query(
            "UPDATE scans SET status='completed', finished_at=%s WHERE id=%s",
            (datetime.utcnow(), scan_id), fetch=False,
        )
    except NotAuthorizedError as exc:
        query(
            "UPDATE scans SET status='failed', error_message=%s, finished_at=%s WHERE id=%s",
            (str(exc), datetime.utcnow(), scan_id), fetch=False,
        )
    except Exception as exc:  # keep the worker thread from dying silently
        query(
            "UPDATE scans SET status='failed', error_message=%s, finished_at=%s WHERE id=%s",
            (str(exc), datetime.utcnow(), scan_id), fetch=False,
        )
