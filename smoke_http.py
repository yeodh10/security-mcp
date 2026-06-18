"""
원격(Streamable HTTP) + Bearer 인증 스모크.

서버를 HTTP 모드로 띄워 검증한다:
  1) /healthz            → 200 (인증 면제)
  2) 토큰 없이 POST /mcp → 401
  3) 올바른 토큰으로 MCP 핸드셰이크 → list_tools (도구 4개)

실행:  python smoke_http.py
(stdio 프로토콜 스모크는 smoke_mcp.py 참고.)
"""

import asyncio
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("SMOKE_PORT", "8765"))
TOKEN = "smoke-token-123"
BASE = f"http://127.0.0.1:{PORT}"


def _get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _post(path, headers=None):
    req = urllib.request.Request(BASE + path, data=b"{}", method="POST", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def wait_ready(timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if _get("/healthz") == 200:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


async def authed_handshake():
    async with streamablehttp_client(
        BASE + "/mcp", headers={"Authorization": f"Bearer {TOKEN}"}
    ) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            tools = await s.list_tools()
            return [t.name for t in tools.tools]


def main():
    env = dict(os.environ, SECURITY_MCP_TRANSPORT="streamable-http", SECURITY_MCP_TOKEN=TOKEN,
               SECURITY_MCP_HOST="127.0.0.1", SECURITY_MCP_PORT=str(PORT), PYTHONUTF8="1")
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready():
            print("서버가 안 떴습니다(healthz 타임아웃).")
            return 1
        print("healthz            :", _get("/healthz"), "(기대 200)")
        print("no-token POST /mcp :", _post("/mcp", {"content-type": "application/json"}), "(기대 401)")
        names = asyncio.run(authed_handshake())
        print("authed list_tools  :", names)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
