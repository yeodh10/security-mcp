# Security Tools MCP — 원격(Streamable HTTP) 컨테이너 이미지.
#   빌드:  docker build -t security-mcp .
#   실행:  docker run -p 8000:8000 -e SECURITY_MCP_TOKEN=<토큰> security-mcp
# 토큰은 런타임 주입 — 이미지에 굽지 않는다. 토큰 없으면 서버가 fail-closed(시작 거부).
FROM python:3.12-slim

WORKDIR /app

# 런타임 의존성만(= mcp). dev(pytest)는 이미지에 넣지 않음.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 앱 소스(테스트·스모크·예시는 .dockerignore로 제외).
COPY *.py ./

# 원격 HTTP 모드 기본값 — 운영 시 SECURITY_MCP_TOKEN만 주입하면 된다.
ENV SECURITY_MCP_TRANSPORT=streamable-http \
    SECURITY_MCP_HOST=0.0.0.0 \
    SECURITY_MCP_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# liveness: 인증 면제 /healthz
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status==200 else 1)"

# 비루트 실행
RUN useradd -m app && chown -R app /app
USER app

CMD ["python", "server.py"]
