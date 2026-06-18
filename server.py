"""
보안 도구 MCP 서버 — Claude(Desktop/Code 등 MCP 클라이언트)가 직접 호출하는 보안 도구 모음.

노출 도구:
  1) scan_prompt_injection — 입력의 프롬프트 인젝션·탈옥 시도 검사 (오프라인, 키 불필요)
  2) lookup_cve            — CVE ID 단건 조회 (심각도·영향 버전·요약, NVD)
  3) find_cves_for_product — 제품 키워드로 최근 CVE 검색 (NVD)
  4) check_cve_affects_version — 특정 CVE가 우리 버전에 영향을 주는지 판정

실행(보통은 MCP 클라이언트가 자동 실행):  python server.py
검증 도구로는: mcp dev server.py  또는 tests/test_tools.py

설계 메모: 도구 출력에 '한계'를 함께 담아, 호출하는 LLM이 결과를 과신하지 않도록 한다
(예: 룰 레이어는 다국어·패러프레이즈를 놓칠 수 있음).
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

import cve
import rules
import versions

mcp = FastMCP("security-tools")


@mcp.tool()
def scan_prompt_injection(text: str) -> dict:
    """사용자 입력/프롬프트에 프롬프트 인젝션·탈옥(jailbreak) 시도가 있는지 검사한다.

    신뢰할 수 없는 사용자 입력을 LLM에 전달하기 전에 점검할 때 사용. 룰/시그니처 +
    역난독화(리트스피크·제로폭·동형문자·base64/hex/ROT13)로 동작하며 키가 필요 없다.

    Args:
        text: 검사할 입력 텍스트.

    Returns:
        decision(block|review|allow), risk_score(0~100), is_malicious,
        matched_categories(공격 유형), evidence(원문 내 의심 구간), note(한계 고지).
    """
    text = text or ""
    r = rules.scan(text)
    spans = rules.detect_spans(text)
    if r["score"] >= rules.BLOCK_THRESHOLD:
        decision = "block"
    elif r["score"] >= rules.FLAG_THRESHOLD:
        decision = "review"
    else:
        decision = "allow"
    return {
        "decision": decision,
        "risk_score": r["score"],
        "is_malicious": decision != "allow",
        "matched_categories": sorted({h["category"] for h in r["hits"]}),
        "evidence": [text[s["start"]:s["end"]] for s in spans][:8],
        "signals": r["signals"],
        "note": "1차 룰 레이어(역난독화 포함). 다국어·의미 패러프레이즈는 놓칠 수 있어, "
                "고위험 맥락에선 2차 LLM 판정을 함께 쓰는 것이 좋다.",
    }


@mcp.tool()
def lookup_cve(cve_id: str) -> dict:
    """특정 CVE의 심각도·CVSS·영향 제품/버전 범위·요약을 NVD에서 조회한다.

    "이 CVE 위험해?", "CVE-2026-1234 뭐야?" 같은 질문에 사용.

    Args:
        cve_id: 예) "CVE-2026-44170".

    Returns:
        id·severity·cvss_score·description·affected_ranges·references·nvd_url 등.
        영향 버전 범위는 affected_ranges에, 사람이 읽는 요약은 affected_versions_summary에.
    """
    c = cve.lookup(cve_id)
    if "error" in c:
        return c
    c["affected_versions_summary"] = versions.affected_summary(c) or ["(NVD에 버전 범위 정보 없음)"]
    return c


@mcp.tool()
def find_cves_for_product(product: str, days: int = 14, max_results: int = 10) -> dict:
    """특정 제품에 영향을 주는 최근 CVE를 NVD에서 찾는다(제품 키워드 매칭).

    "최근 mariadb 취약점 있어?", "apache 관련 CVE 찾아줘" 같은 질문에 사용.
    주의: 제품 *식별*은 키워드 수준이라(예: apache는 HTTP/CXF/Struts 통칭) 과탐 여지가 있다.

    Args:
        product: 제품 키워드. 예) "mariadb", "apache", "fortinet", "windows".
        days: 최근 며칠(기본 14, 최대 120).
        max_results: 최대 반환 수(기본 10).

    Returns:
        count와 cves 리스트(심각도순). 각 항목에 영향 버전 요약 포함.
    """
    try:
        items = cve.search_product(product, days=days, max_results=max_results)
    except RuntimeError as e:
        return {"error": str(e), "cves": []}
    for c in items:
        c["affected_versions_summary"] = versions.affected_summary(c) or ["(범위 정보 없음)"]
    return {
        "product": product,
        "days": days,
        "count": len(items),
        "cves": items,
        "note": "제품 식별은 키워드 수준이라 동명이품(예: 여러 Apache 프로젝트)이 섞일 수 있음.",
    }


@mcp.tool()
def check_cve_affects_version(cve_id: str, product: str, version: str) -> dict:
    """특정 CVE가 '우리가 쓰는 제품의 특정 버전'에 실제로 영향을 주는지 판정한다.

    과알림을 줄이는 핵심 도구. "우리는 mariadb 10.6.30 쓰는데 CVE-2026-44170 영향 받아?"에 사용.

    Args:
        cve_id: 예) "CVE-2026-44170".
        product: 제품 키워드. 예) "mariadb".
        version: 우리 버전. 예) "10.6.30".

    Returns:
        affected(true=영향/false=안 받음/null=판단 불가), affected_ranges,
        explanation. NVD에 버전 범위가 없으면 affected=null.
    """
    c = cve.lookup(cve_id)
    if "error" in c:
        return c
    verdict = versions.cve_affects_version(c, product, version)
    summ = versions.affected_summary(c)
    if verdict is True:
        expl = f"{product} {version}은(는) 취약 범위에 들어갑니다 → 영향 받음."
    elif verdict is False:
        expl = f"{product} {version}은(는) 취약 범위 밖입니다 → 영향 받지 않음(패치/안전 버전)."
    else:
        expl = "판단 불가 — NVD에 해당 제품의 버전 범위가 없거나 제품명이 매칭되지 않습니다."
    return {
        "cve_id": c["id"],
        "product": product,
        "version": version,
        "affected": verdict,
        "affected_ranges_summary": summ or ["(범위 정보 없음)"],
        "severity": c["severity"],
        "explanation": expl,
        "nvd_url": c["nvd_url"],
    }


if __name__ == "__main__":
    mcp.run()
