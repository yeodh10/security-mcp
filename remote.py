"""
원격 transport(Streamable HTTP / SSE) + 최소 인증(공유 Bearer 토큰).

기본은 stdio(로컬 MCP 클라이언트가 실행). 환경변수로 원격 HTTP 모드를 켠다:
  SECURITY_MCP_TRANSPORT     = stdio(기본) | streamable-http | http(별칭) | sse
  SECURITY_MCP_TOKEN         = (HTTP/SSE 필수) 공유 Bearer 토큰. 쉼표로 여러 개 = 무중단 회전(old,new)
  SECURITY_MCP_HOST          = 바인드 호스트(기본 127.0.0.1; 컨테이너는 0.0.0.0)
  SECURITY_MCP_PORT          = 포트(기본 8000; 미설정 시 PaaS의 PORT 환경변수를 자동 사용 — Render/Heroku 등)
  SECURITY_MCP_RATE_LIMIT    = IP별 윈도우당 요청 수(기본 120, 0=끔)
  SECURITY_MCP_RATE_WINDOW   = 레이트리밋 윈도우 초(기본 60)
  SECURITY_MCP_ALLOWED_HOSTS = (선택) 쉼표구분. 설정 시 DNS-rebinding 보호 ON.
                               예) "example.com,localhost:*" (":*" = 임의 포트)

설계:
- 정적 공유 토큰에 FastMCP의 OAuth(AuthSettings: issuer/resource URL 강제) 틀은 과하고 부정직하다.
  대신 streamable_http_app()/sse_app()이 주는 ASGI 앱을 '스트리밍 안전한 raw ASGI 미들웨어'로 감싸
  Authorization: Bearer 토큰만 검사한다(스트리밍 응답을 깨지 않도록 BaseHTTPMiddleware 대신 raw ASGI).
- 토큰 비교는 hmac.compare_digest로 상수시간(타이밍 공격 방지).
- uvicorn은 HTTP 모드에서만 lazy import → stdio 경로·런타임 의존성에 영향 없음(여전히 mcp만).
- /healthz는 인증 없이 200(배포 liveness 체크용).

정직한 한계: 공유 토큰(멀티테넌트·스코프 없음; 회전은 멀티토큰으로만). TLS는 앞단(reverse proxy)에서.
레이트리밋은 단일 프로세스 메모리 기준(다중 워커·분산 환경은 별도 저장소 필요), 프록시 뒤면 IP가 프록시로 보임.
"""

from __future__ import annotations

import hmac
import os
import time

from mcp.server.transport_security import TransportSecuritySettings

HEALTH_PATH = "/healthz"


def token_ok(auth_header: str, expected) -> bool:
    """Authorization 헤더가 'Bearer <유효 토큰 중 하나>'인지 상수시간 비교(순수 함수).

    expected는 단일 토큰(str) 또는 여러 유효 토큰(리스트). 여러 개를 두면 무중단 회전이 된다
    (old+new 동시 허용 → 클라이언트 이전 후 old 제거). 비어 있으면(설정 오류) 항상 거부.
    """
    candidates = [expected] if isinstance(expected, str) else list(expected or [])
    prefix = "Bearer "
    if not auth_header or not auth_header.startswith(prefix):
        return False
    presented = auth_header[len(prefix):].strip()
    ok = False
    for t in candidates:
        if t and hmac.compare_digest(presented, t):
            ok = True  # 단락 없이 모든 후보를 검사(어느 토큰이 맞았는지 타이밍 누출 최소화)
    return ok


def _resolve_port() -> int:
    """포트 우선순위: SECURITY_MCP_PORT > PORT(PaaS 관례) > 8000.

    Render/Heroku 등은 런타임에 PORT를 주입하고 거기로 라우팅한다 — 그대로 받게 한다.
    """
    return int(os.environ.get("SECURITY_MCP_PORT") or os.environ.get("PORT") or "8000")


def transport_security_from_env():
    """SECURITY_MCP_ALLOWED_HOSTS가 있으면 DNS-rebinding 보호를 켠 설정, 없으면 None(기본=보호 off).

    원격 배포 시 Host/Origin 위조를 막는 하드닝 노브. 로컬 데모는 미설정으로 그냥 동작.
    """
    raw = os.environ.get("SECURITY_MCP_ALLOWED_HOSTS", "").strip()
    if not raw:
        return None
    hosts = [h.strip() for h in raw.split(",") if h.strip()]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=hosts,
    )


async def _respond(send, status: int, body: bytes, extra=()):
    headers = [(b"content-type", b"application/json")] + list(extra)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class BearerAuthMiddleware:
    """공유 Bearer 토큰을 강제하는 raw ASGI 미들웨어(스트리밍 안전).

    - lifespan 등 비-HTTP scope는 그대로 통과(세션매니저 startup 보존).
    - /healthz는 인증 없이 200.
    - 토큰 불일치/누락 → 401(JSON + WWW-Authenticate).
    """

    def __init__(self, app, token: str, health_path: str = HEALTH_PATH):
        self.app = app
        self.token = token
        self.health_path = health_path

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("path") == self.health_path:
            await _respond(send, 200, b'{"status":"ok"}')
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        if not token_ok(auth, self.token):
            await _respond(send, 401, b'{"error":"unauthorized"}',
                           extra=[(b"www-authenticate", b'Bearer realm="security-mcp"')])
            return
        await self.app(scope, receive, send)


class RateLimiter:
    """고정 윈도우 레이트리밋(키별, 프로세스 메모리). limit<=0이면 비활성(순수 로직, 테스트 가능)."""

    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self._buckets: dict = {}

    def allow(self, key, now: float) -> bool:
        if self.limit <= 0:
            return True
        start, count = self._buckets.get(key, (now, 0))
        if now - start >= self.window:
            start, count = now, 0
        count += 1
        self._buckets[key] = (start, count)
        # 만료 버킷 정리 — 분산 IP 대량 유입 시 dict 무한 증가(메모리 고갈) 방지.
        if len(self._buckets) > 10000:
            self._buckets = {k: (s, c) for k, (s, c) in self._buckets.items()
                             if now - s < self.window}
        return count <= self.limit


class RateLimitMiddleware:
    """클라이언트 IP별 레이트리밋 raw ASGI 미들웨어(최외곽). 초과 → 429. /healthz 면제.

    인증 전에 두어 무토큰 플러드까지 IP 단위로 제한한다(프록시 뒤면 실제 IP는 X-Forwarded-For —
    여기선 scope client 기준; 정직한 단순화).
    """

    def __init__(self, app, limiter: RateLimiter, exempt=(HEALTH_PATH,)):
        self.app = app
        self.limiter = limiter
        self.exempt = set(exempt)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in self.exempt:
            await self.app(scope, receive, send)
            return
        client = scope.get("client") or ("?", 0)
        if not self.limiter.allow(client[0], time.time()):
            await _respond(send, 429, b'{"error":"rate_limited"}',
                           extra=[(b"retry-after", str(self.limiter.window).encode())])
            return
        await self.app(scope, receive, send)


def serve(mcp) -> None:
    """환경변수에 따라 stdio(기본) 또는 인증·레이트리밋된 원격 HTTP/SSE로 서버를 띄운다.

    server.py의 __main__이 mcp.run() 대신 이걸 호출한다.
    """
    transport = os.environ.get("SECURITY_MCP_TRANSPORT", "stdio").strip().lower()
    if transport in ("", "stdio"):
        mcp.run()
        return

    # 토큰: 쉼표로 여러 개 가능(무중단 회전 — old+new 동시 허용)
    tokens = [t.strip() for t in (os.environ.get("SECURITY_MCP_TOKEN") or "").split(",") if t.strip()]
    if not tokens:
        raise SystemExit("원격 transport에는 SECURITY_MCP_TOKEN(공유 Bearer 토큰, 쉼표로 여러 개 가능)이 필요합니다.")
    host = os.environ.get("SECURITY_MCP_HOST", "127.0.0.1")
    port = _resolve_port()

    if transport in ("streamable-http", "http"):
        app = mcp.streamable_http_app()
    elif transport == "sse":
        app = mcp.sse_app()
    else:
        raise SystemExit(f"알 수 없는 SECURITY_MCP_TRANSPORT: {transport!r} "
                         "(stdio|streamable-http|sse)")

    app = BearerAuthMiddleware(app, tokens)
    limit = int(os.environ.get("SECURITY_MCP_RATE_LIMIT", "120"))    # 윈도우당 요청 수(0=끔)
    window = int(os.environ.get("SECURITY_MCP_RATE_WINDOW", "60"))   # 윈도우 길이(초)
    app = RateLimitMiddleware(app, RateLimiter(limit, window))       # 인증보다 바깥(플러드 차단)
    import uvicorn  # HTTP 모드에서만 필요 — mcp가 이미 끌어온 의존성(새 의존성 아님)

    uvicorn.run(app, host=host, port=port, log_level="info")
