# VENDOR — 복사된(vendored) 로직의 출처와 동기화

이 repo의 일부 모듈은 다른 프로젝트의 **검증된 로직을 복사**해 온 것입니다(MCP 도구로 노출하려고).
단일 출처가 아니라 복사본이므로 원본이 바뀌면 **수동 동기화**가 필요합니다. 이 문서는 그 출처와
한계를 명시해 공급망/provenance를 투명하게 둡니다.

## 복사 목록

| 파일 | 출처 repo | 영역 |
|---|---|---|
| `rules.py` | https://github.com/yeodh10/prompt-guard | 인젝션 시그니처 + 스캔 |
| `normalize.py` | https://github.com/yeodh10/prompt-guard | 매칭 전 역난독화 |
| `cve.py` | https://github.com/yeodh10/cve-radar | NVD 조회·정규화 |
| `versions.py` | https://github.com/yeodh10/cve-radar | 버전 비교·영향 판정 |

> 위 파일들은 원본을 **수동 복사**한 것으로, 특정 upstream 커밋에 **핀 고정돼 있지 않습니다**.
> 재동기화는 각 원본 repo와 diff 떠서 반영하는 방식(자동화 없음).

## 왜 복사인가 / 진짜 해결책

복사는 "이 repo 하나로 데모가 돈다"는 자족성을 주지만 **중복**이라는 부채가 있습니다.
부채를 진짜로 없애려면(택1):

1. **공유 패키지 추출** — prompt-guard·cve-radar의 공통 로직을 별도 패키지로 publish(PyPI/private)하고
   세 repo가 모두 그것을 의존. 가장 깔끔하지만 **외부 repo 3곳 작업** 필요.
2. **git subtree / submodule** — 원본 repo를 하위 트리/서브모듈로 연결해 단일 출처 유지.
3. **(현재) provenance 매니페스트** — 이 문서로 출처·동기화 한계를 문서화해 부채를 *관리*.
   복사를 제거하진 못하지만(제거엔 외부 repo가 필요) 가장 가볍고 **이 repo만으로 완결**.

현재는 **3**을 택했습니다 — 외부 repo 접근/배포 인프라 없이 이 repo만으로 가능한 정직한 선택.
1·2로 올리는 건 외부 repo 작업이 가능해질 때의 다음 단계입니다.
