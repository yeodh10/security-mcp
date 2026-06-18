"""
버전 비교 + "이 CVE가 특정 버전에 영향을 주는가" 판정.

키워드 매칭만으로는 "MariaDB 쓰네 → MariaDB CVE 다 표시"가 되어 과알림이 난다.
NVD의 취약 버전 범위(affected_ranges)와 사용자가 입력한 버전을 대조해
'영향 받음 / 안 받음 / 판단 불가'를 가른다 → 과알림 감소의 핵심.

버전 비교는 완전한 SemVer/PEP440이 아니라 'CVE에 흔한 점-구분 버전'에 맞춘
실용적 비교다(예: 10.6.26, 1.29.1, 5.6.19.24).
"""

from __future__ import annotations

import re

_SPLIT = re.compile(r"[.\-_+]")
_NUMTAIL = re.compile(r"^(\d+)([A-Za-z].*)?$")


def parse_version(v) -> tuple:
    """'10.6.26' → 비교 가능한 튜플. 숫자는 숫자대로, 비숫자는 뒤로 정렬되게."""
    if v is None:
        return ()
    out = []
    for part in _SPLIT.split(str(v).strip()):
        if part == "":
            continue
        m = _NUMTAIL.match(part)
        if m:
            out.append((0, int(m.group(1)), m.group(2) or ""))
        else:
            out.append((1, 0, part.lower()))
    return tuple(out)


def cmp_version(a, b) -> int:
    """a<b → -1, a==b → 0, a>b → 1 (길이 다르면 짧은 쪽을 0으로 패딩)."""
    pa, pb = list(parse_version(a)), list(parse_version(b))
    pad = (0, 0, "")
    n = max(len(pa), len(pb))
    pa += [pad] * (n - len(pa))
    pb += [pad] * (n - len(pb))
    return (pa > pb) - (pa < pb)


def is_affected(user_version, rng: dict):
    """user_version이 취약 범위(rng) 안에 드는가. 판단 불가면 None."""
    if not user_version:
        return None
    uv = str(user_version).strip()

    if rng.get("version"):  # 특정 버전만 취약
        return cmp_version(uv, rng["version"]) == 0

    start, end = rng.get("start"), rng.get("end")
    if not start and not end:
        return None  # 범위 정보 없음 → 판단 불가

    ok = True
    if start:
        c = cmp_version(uv, start)
        ok = ok and (c >= 0 if rng.get("start_incl") else c > 0)
    if end:
        c = cmp_version(uv, end)
        ok = ok and (c <= 0 if rng.get("end_incl") else c < 0)
    return ok


def cve_affects_version(cve: dict, product_hint: str, user_version: str):
    """product_hint(제품 키워드)에 맞는 취약 범위가 user_version에 영향을 주는지.

    반환: True(영향) / False(안 받음) / None(판단 불가 — 범위정보 없음·제품 불일치).
    하나라도 '영향'이면 영향으로 본다(보수적).
    """
    ph = (product_hint or "").lower().strip()
    verdicts = []
    for rng in cve.get("affected_ranges", []) or []:
        hay = f"{rng.get('product', '')} {rng.get('vendor', '')}".lower()
        if ph and ph not in hay:
            continue
        v = is_affected(user_version, rng)
        if v is not None:
            verdicts.append(v)
    if not verdicts:
        return None
    return any(verdicts)


def range_text(rng: dict) -> str:
    """범위 하나를 사람이 읽는 표기로: '= 12.3.1' 또는 '≥10.6.1, <10.6.26'."""
    if rng.get("version"):
        return f"= {rng['version']}"
    bits = []
    if rng.get("start"):
        bits.append(("≥" if rng.get("start_incl") else ">") + str(rng["start"]))
    if rng.get("end"):
        bits.append(("≤" if rng.get("end_incl") else "<") + str(rng["end"]))
    return ", ".join(bits) or "(범위 불명)"


def affected_summary(cve: dict, max_items: int = 4) -> list[str]:
    """CVE의 영향 버전 범위를 '제품 범위' 짧은 요약 리스트로(중복 제거)."""
    seen, out = set(), []
    for rng in cve.get("affected_ranges", []) or []:
        t = f"{rng.get('product', '?')} {range_text(rng)}"
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out[:max_items]
