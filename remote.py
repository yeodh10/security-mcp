"""
원격 transport(Streamable HTTP / SSE) + 최소 인증(공유 Bearer 토큰).

기본은 stdio(로컬 MCP 클라이언트가 실행). 환경변수로 원격 HTTP 모드를 켠다:
  SECURITY_MCP_TRANSPORT     = stdio(기본) | streamable-http | http(별칭) | sse
  SECURITY_MCP_TOKEN         = (HTTP/SSE 필수) 공유 Bearer 토큰
  SECURITY_MCP_HOST          = 바인드 호스트(기본 127.0.0.1)
  SECURITY_MCP_PORT          = 포트(기본 8000)
  SECURITY_MCP_ALLOWED_HOSTS = (선택) 쉼표구분. 설정 시 DNS-rebinding 보호 ON.
                               예) "example.com,localhost:*" (":*" = 임의 포트)

설계:
- 정적 공유 토큰에 FastMCP의 OAuth(AuthSettings: issuer/resource URL 강제) 틀은 과하고 부정직하다.
  대신 streamable_http_app()/sse_app()이 주는 ASGI 앱을 '스트리밍 안전한 raw ASGI 미들웨어'로 감싸
  Authorization: Bearer 토큰만 검사한다(스트리밍 응답을 깨지 않도록 BaseHTTPMiddleware 대신 raw ASGI).
- 토큰 비교는 hmac.compare_digest로 상수시간(타이밍 공격 방지).
- uvicorn은 HTTP 모드에서만 lazy import → stdio 경로·런타임 의존성에 영향 없음(여전히 mcp만).
- /healthz는 인증 없이 200(배포 liveness 체크용).

정직한 한계: 단일 공유 토큰(멀티테넌트·스코프·회전 없음). TLS는 앞단(reverse proxy)에서. 레이트리밋 미구현.
"""

from __future__ import annotations

import hmac
import os

from mcp.server.transport_security import TransportSecuritySettings

HEALTH_PATH = "/healthz"


def token_ok(auth_header: str, expected: str) -> bool:
    """Authorization 헤더가 'Bearer <expected>'인지 상수시간 비교로 확인(순수 함수).

    expected가 비어 있으면(설정 오류) 항상 거부한다.
    """
    if not expected:
        return False
    prefix = "Bearer "
    if not auth_header or not auth_header.startswith(prefix):
        return False
    return hmac.compare_digest(auth_header[len(prefix):].strip(), expected)


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


def serve(mcp) -> None:
    """환경변수에 따라 stdio(기본) 또는 인증된 원격 HTTP/SSE로 서버를 띄운다.

    server.py의 __main__이 mcp.run() 대신 이걸 호출한다.
    """
    transport = os.environ.get("SECURITY_MCP_TRANSPORT", "stdio").strip().lower()
    if transport in ("", "stdio"):
        mcp.run()
        return

    token = os.environ.get("SECURITY_MCP_TOKEN")
    if not token:
        raise SystemExit("원격 transport에는 SECURITY_MCP_TOKEN(공유 Bearer 토큰)이 필요합니다.")
    host = os.environ.get("SECURITY_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("SECURITY_MCP_PORT", "8000"))

    if transport in ("streamable-http", "http"):
        app = mcp.streamable_http_app()
    elif transport == "sse":
        app = mcp.sse_app()
    else:
        raise SystemExit(f"알 수 없는 SECURITY_MCP_TRANSPORT: {transport!r} "
                         "(stdio|streamable-http|sse)")

    app = BearerAuthMiddleware(app, token)
    import uvicorn  # HTTP 모드에서만 필요 — mcp가 이미 끌어온 의존성(새 의존성 아님)

    uvicorn.run(app, host=host, port=port, log_level="info")
