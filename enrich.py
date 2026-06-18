"""
CVE 위협 인텔 보강 — KEV(실제 악용 중)·EPSS(악용 확률).

NVD의 심각도(CVSS)는 '얼마나 심각할 수 있나'지 '지금 실제로 악용되나'가 아니다.
- CISA KEV: 실제 악용이 관측된 취약점 카탈로그(미국 정부). 들어 있으면 '지금 급함'.
- EPSS(FIRST): 향후 30일 내 악용될 확률(0~1)과 백분위.
둘을 합쳐 'CVSS 심각도'가 아니라 '실제 위급도'로 우선순위를 잡게 한다(과알림 감소의 또 다른 축).

정직한 한계:
- KEV '없음'은 '안전'이 아니다 — 미관측·미등재일 수 있다(특히 비미국·신규 취약점).
- EPSS는 확률 추정치다(관측이 아님).
- 네트워크 실패 시 에러로 막지 않고 '판단 보류(None)'로 돌려, 소비 LLM이 과신/오작동하지 않게 한다.

테스트 용이성: 파싱(`_parse_kev`/`_parse_epss`)은 네트워크 없는 순수 함수로 분리.
서버는 `exploitation()`만 호출하므로 테스트에서 통째로 monkeypatch 가능.
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
_UA = {"User-Agent": "security-mcp/1.0"}

# KEV 카탈로그는 ~1MB대라 매번 받지 않고 캐시한다(프로세스 수명 동안, TTL 6시간).
_KEV_TTL = 6 * 3600
_kev_cache: dict = {"fetched_at": 0.0, "by_id": None}


def _fetch_json(url: str, attempts: int = 3) -> dict:
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers=_UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"위협 인텔 요청 실패(일시적 장애일 수 있음): {last}")


# ── KEV ────────────────────────────────────────────────────────
def _parse_kev(catalog: dict, cve_id: str) -> dict:
    """KEV 카탈로그(raw JSON)에서 cve_id 등재 여부·메타를 뽑는다(순수 함수)."""
    cid = (cve_id or "").strip().upper()
    for v in catalog.get("vulnerabilities", []) or []:
        if (v.get("cveID") or "").upper() == cid:
            ransom = (v.get("knownRansomwareCampaignUse") or "").strip().lower()
            return {
                "in_kev": True,
                "date_added": v.get("dateAdded", ""),
                "due_date": v.get("dueDate", ""),
                "known_ransomware": ransom == "known",
                "vendor_project": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "vuln_name": v.get("vulnerabilityName", ""),
                "source": "CISA KEV",
            }
    return {"in_kev": False, "source": "CISA KEV"}


def _kev_catalog() -> dict:
    now = time.time()
    if _kev_cache["by_id"] is None or (now - _kev_cache["fetched_at"]) > _KEV_TTL:
        catalog = _fetch_json(KEV_FEED)
        _kev_cache["by_id"] = catalog
        _kev_cache["fetched_at"] = now
    return _kev_cache["by_id"]


def kev_status(cve_id: str) -> dict:
    """CVE가 CISA KEV(실제 악용 카탈로그)에 등재됐는지. 조회 실패 시 in_kev=None."""
    try:
        return _parse_kev(_kev_catalog(), cve_id)
    except RuntimeError as e:
        return {"in_kev": None, "error": str(e), "source": "CISA KEV"}


def kev_flags(cve_ids) -> dict:
    """여러 CVE의 KEV 등재 여부를 카탈로그 1회 조회로 일괄 판정(목록 보강용).

    Returns: {cve_id: kev_dict}. 조회 실패 시 RuntimeError(호출측이 graceful 처리).
    """
    catalog = _kev_catalog()
    return {cid: _parse_kev(catalog, cid) for cid in cve_ids}


# ── EPSS ───────────────────────────────────────────────────────
def _parse_epss(resp: dict, cve_id: str) -> dict:
    """EPSS API 응답(raw JSON)에서 점수·백분위를 뽑는다(순수 함수)."""
    cid = (cve_id or "").strip().upper()
    for d in resp.get("data", []) or []:
        if (d.get("cve") or "").upper() == cid:
            try:
                epss = float(d.get("epss")) if d.get("epss") is not None else None
            except (TypeError, ValueError):
                epss = None
            try:
                pct = float(d.get("percentile")) if d.get("percentile") is not None else None
            except (TypeError, ValueError):
                pct = None
            return {"epss": epss, "percentile": pct, "date": d.get("date", ""), "source": "FIRST EPSS"}
    return {"epss": None, "note": "EPSS에 해당 CVE 데이터 없음(신규이거나 미산정).", "source": "FIRST EPSS"}


def epss_score(cve_id: str) -> dict:
    """CVE의 EPSS(향후 30일 악용 확률)·백분위. 조회 실패 시 epss=None."""
    cid = (cve_id or "").strip().upper()
    try:
        resp = _fetch_json(f"{EPSS_API}?cve={urllib.parse.quote(cid)}")
    except RuntimeError as e:
        return {"epss": None, "error": str(e), "source": "FIRST EPSS"}
    return _parse_epss(resp, cid)


# ── 합산: 실제 위급도 판정 ──────────────────────────────────────
def _priority(kev: dict, epss: dict) -> tuple[str, str]:
    """(level, 한국어 설명). level ∈ critical|high|medium|low|unknown."""
    if kev.get("in_kev") is True:
        extra = " · 랜섬웨어 캠페인 악용 보고" if kev.get("known_ransomware") else ""
        return "critical", f"긴급 — CISA KEV 등재(실제 악용 관측){extra}. CVSS와 무관하게 우선 대응."
    e = epss.get("epss")
    if e is not None:
        pct = epss.get("percentile")
        pct_txt = f", 상위 {round((1 - pct) * 100, 1)}%" if isinstance(pct, (int, float)) else ""
        if e >= 0.5:
            return "high", f"높음 — EPSS {round(e, 3)}(악용 확률 높음{pct_txt})."
        if e >= 0.1:
            return "medium", f"중간 — EPSS {round(e, 3)}(악용 가능성 일부{pct_txt})."
        return "low", f"낮음 — EPSS {round(e, 3)}(알려진 악용 신호 약함{pct_txt})."
    if kev.get("in_kev") is None and e is None:
        return "unknown", "판단 보류 — KEV/EPSS 조회 실패(네트워크). '안전'이 아님."
    return "low", "낮음 — KEV 미등재 · EPSS 데이터 없음. (미관측일 수 있어 '안전' 단정 금지.)"


def exploitation(cve_id: str) -> dict:
    """CVE의 '실제 위급도' 한 묶음: KEV + EPSS + 우선순위 힌트.

    Returns:
        kev, epss, exploitation_level(critical|high|medium|low|unknown),
        priority(한국어 설명), note(한계 고지).
    """
    kev = kev_status(cve_id)
    epss = epss_score(cve_id)
    level, priority = _priority(kev, epss)
    return {
        "kev": kev,
        "epss": epss,
        "exploitation_level": level,
        "priority": priority,
        "note": "KEV/EPSS는 '실제 악용' 신호(↔ CVSS는 '잠재 심각도'). "
                "KEV '없음'은 안전이 아니라 '미관측'일 수 있고, EPSS는 확률 추정치임.",
    }
