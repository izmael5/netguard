import os
import threading
from flask import Flask, render_template, request, jsonify, send_file, abort
from flask_cors import CORS

from config import Config
from database.db import query
from scanner import run_full_scan
from scanner.authorization import is_authorized
from report.report_generator import generate_html_report

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)


@app.route("/")
def index():
    scans = query("SELECT * FROM scans ORDER BY started_at DESC LIMIT 25")
    targets = query("SELECT * FROM allowed_targets ORDER BY added_at DESC")
    return render_template("index.html", scans=scans, targets=targets)


@app.route("/targets", methods=["POST"])
def add_target():
    data = request.form or request.json or {}
    target = (data.get("target") or "").strip()
    label = (data.get("label") or "").strip()
    ttype = data.get("target_type", "host")
    if not target:
        return jsonify({"error": "target is required"}), 400
    query(
        "INSERT IGNORE INTO allowed_targets (target, label, target_type) VALUES (%s,%s,%s)",
        (target, label, ttype), fetch=False,
    )
    return jsonify({"ok": True})


@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.form or request.json or {}
    target = (data.get("target") or "").strip()
    scan_type = data.get("scan_type", "full")
    port_range = data.get("port_range", Config.DEFAULT_PORT_RANGE)

    if not target:
        return jsonify({"error": "target is required"}), 400
    if not is_authorized(target):
        return jsonify({
            "error": f"'{target}' is not in your allowed_targets list. "
                     f"Add it first (you must own it or have written permission to test it)."
        }), 403

    scan_id = query(
        "INSERT INTO scans (target, scan_type, port_range, status) VALUES (%s,%s,%s,'queued')",
        (target, scan_type, port_range), fetch=False,
    )

    thread = threading.Thread(
        target=run_full_scan, args=(scan_id, target, scan_type, port_range), daemon=True
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"})


@app.route("/scan/<int:scan_id>")
def scan_status(scan_id):
    rows = query("SELECT * FROM scans WHERE id=%s", (scan_id,))
    if not rows:
        abort(404)
    scan = rows[0]
    ports = query("SELECT * FROM scan_ports WHERE scan_id=%s ORDER BY port", (scan_id,))
    vulns = query("SELECT * FROM vulnerabilities WHERE scan_id=%s ORDER BY cvss_score DESC", (scan_id,))
    web_findings = query("SELECT * FROM web_findings WHERE scan_id=%s", (scan_id,))
    return render_template(
        "results.html", scan=scan, ports=ports, vulns=vulns, web_findings=web_findings
    )


@app.route("/api/scan/<int:scan_id>")
def api_scan_status(scan_id):
    rows = query("SELECT * FROM scans WHERE id=%s", (scan_id,))
    if not rows:
        return jsonify({"error": "not found"}), 404
    scan = rows[0]
    scan["started_at"] = str(scan["started_at"])
    scan["finished_at"] = str(scan["finished_at"]) if scan["finished_at"] else None
    return jsonify(scan)


@app.route("/report/<int:scan_id>", methods=["POST"])
def make_report(scan_id):
    rows = query("SELECT * FROM scans WHERE id=%s", (scan_id,))
    if not rows:
        abort(404)
    if rows[0]["status"] != "completed":
        return jsonify({"error": "scan not completed yet"}), 400
    path = generate_html_report(scan_id)
    return jsonify({"ok": True, "download_url": f"/report/{scan_id}/download"})


@app.route("/report/<int:scan_id>/download")
def download_report(scan_id):
    rows = query(
        "SELECT * FROM reports WHERE scan_id=%s ORDER BY created_at DESC LIMIT 1", (scan_id,)
    )
    if not rows:
        abort(404)
    return send_file(rows[0]["file_path"], as_attachment=True)


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=Config.DEBUG)
