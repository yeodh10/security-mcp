"""
NVD CVE 조회 (MCP 도구용 lean 버전).

cve-radar의 정규화·버전 로직을 자급자족 형태로 옮긴 것. config/severity 의존 없이
stdlib + versions.py만 쓴다. 단건 조회·제품 검색·버전 영향 판정을 제공한다.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

import versions

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_UA = {"User-Agent": "security-mcp/1.0"}


def _severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _pick_metric(metrics: dict):
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity"), d.get("vectorString")
    arr = metrics.get("cvssMetricV2")
    if arr:
        d = arr[0].get("cvssData", {})
        return d.get("baseScore"), arr[0].get("baseSeverity"), d.get("vectorString")
    return None, None, None


def _parse_cpe_range(cm: dict):
    parts = (cm.get("criteria") or "").split(":")
    if len(parts) < 6:
        return None
    vendor, product, ver = parts[3], parts[4], parts[5]
    specific = ver if ver not in ("*", "-", "") else None
    start = cm.get("versionStartIncluding") or cm.get("versionStartExcluding")
    end = cm.get("versionEndIncluding") or cm.get("versionEndExcluding")
    if not specific and not start and not end:
        return None
    return {"vendor": vendor, "product": product, "version": specific,
            "start": start, "start_incl": "versionStartIncluding" in cm,
            "end": end, "end_incl": "versionEndIncluding" in cm}


def normalize(item: dict) -> dict:
    cve = item.get("cve", item)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, raw_sev, vector = _pick_metric(cve.get("metrics", {}))
    cwe = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwe:
                cwe.append(v)
    affected, ranges = [], []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable", True):
                    continue
                crit = cm.get("criteria")
                if crit and crit not in affected:
                    affected.append(crit)
                r = _parse_cpe_range(cm)
                if r and r not in ranges:
                    ranges.append(r)
    refs = []
    for r in cve.get("references", []):
        u = r.get("url")
        if u and u not in refs:
            refs.append(u)
    sev = (raw_sev or _severity_from_score(score) or "UNKNOWN").upper()
    return {
        "id": cve.get("id", ""),
        "published": (cve.get("published") or "")[:10],
        "severity": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE") else _severity_from_score(score),
        "cvss_score": score,
        "cvss_vector": vector or "",
        "cwe": cwe,
        "description": desc,
        "affected_cpe": affected[:8],
        "affected_ranges": ranges,
        "references": refs[:6],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
        "status": cve.get("vulnStatus", ""),
    }


def _request(params: dict, attempts: int = 3) -> dict:
    qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(f"{NVD}?{qs}", headers=_UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"NVD 요청 실패(일시적 장애일 수 있음): {last}")


def lookup(cve_id: str) -> dict:
    """CVE ID 단건 조회."""
    data = _request({"cveId": cve_id.strip().upper()})
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"{cve_id}을(를) NVD에서 찾지 못했습니다."}
    return normalize(vulns[0])


def search_product(product: str, days: int = 14, max_results: int = 10) -> list[dict]:
    """최근 N일 CVE 중 제품 키워드가 (설명/CPE에) 걸리는 것."""
    from datetime import datetime, timedelta, timezone
    days = max(1, min(days, 120))
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    data = _request({
        "pubStartDate": (now - timedelta(days=days)).strftime(fmt),
        "pubEndDate": now.strftime(fmt),
        "resultsPerPage": 200,
    })
    p = product.lower().strip()
    out = []
    for item in data.get("vulnerabilities", []):
        c = normalize(item)
        hay = (c["description"] + " " + " ".join(c["affected_cpe"])).lower()
        if p in hay:
            out.append(c)
    out.sort(key=lambda c: -(c["cvss_score"] or 0))
    return out[:max_results]
