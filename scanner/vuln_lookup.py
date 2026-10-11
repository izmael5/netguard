"""
Vulnerability identification.

This module ONLY looks up known, publicly-documented CVEs for a detected
product/version using the NVD (National Vulnerability Database) public
API. It does not attempt to exploit anything — it reports "this version
has known CVE-XXXX-YYYY, here is the description and a link to read more
and decide on remediation."
"""
import time
import requests
from config import Config

_last_call = 0.0


def _rate_limit():
    """NVD allows ~5 req/30s without a key, ~50 req/30s with one."""
    global _last_call
    min_interval = 1.2 if not Config.NVD_API_KEY else 0.1
    elapsed = time.time() - _last_call
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _last_call = time.time()


def lookup_cves(product: str, version: str, max_results: int = 8):
    """Query NVD for CVEs matching a product/version string.

    Returns a list of dicts: cve_id, severity, cvss_score, description, url.
    """
    if not product:
        return []

    keyword = f"{product} {version}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    headers = {}
    if Config.NVD_API_KEY:
        headers["apiKey"] = Config.NVD_API_KEY

    _rate_limit()
    try:
        resp = requests.get(Config.NVD_BASE_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return [{
            "cve_id": None, "severity": "UNKNOWN", "cvss_score": None,
            "description": f"CVE lookup failed for '{keyword}': {exc}",
            "reference_url": None,
        }]

    data = resp.json()
    findings = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        metrics = cve.get("metrics", {})
        severity, score = _extract_cvss(metrics)

        findings.append({
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": score,
            "description": desc_text,
            "reference_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        })
    return findings


def _extract_cvss(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = cvss.get("baseScore")
            severity = entries[0].get("baseSeverity") or cvss.get("baseSeverity")
            return severity or "UNKNOWN", score
    return "UNKNOWN", None
