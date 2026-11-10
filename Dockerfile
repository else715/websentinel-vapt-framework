FROM golang:1.24-bookworm AS scanner-tools
ENV GOBIN=/out
RUN mkdir -p /out \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

FROM ghcr.io/zaproxy/zaproxy:stable AS zap

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:/usr/local/bin:/zap:/usr/local/go/bin:${PATH}" \
    ZAP_PATH=/zap/zap.sh \
    IS_CONTAINERIZED=true \
    WEBSENTINEL_DB=/data/websentinel.db \
    WEBSENTINEL_OLLAMA_URL=http://ollama:11434 \
    HOME=/home/websentinel

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap openjdk-17-jre-headless ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system websentinel \
    && useradd --system --gid websentinel --create-home --home-dir /home/websentinel websentinel \
    && mkdir -p /data /zap/wrk /opt/zap \
    && chown -R websentinel:websentinel /data /zap /home/websentinel

COPY --from=scanner-tools /out/subfinder /usr/local/bin/subfinder
COPY --from=scanner-tools /out/httpx /usr/local/bin/httpx
COPY --from=scanner-tools /out/katana /usr/local/bin/katana
COPY --from=scanner-tools /out/nuclei /usr/local/bin/nuclei
COPY --from=zap /zap/ /zap/
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt requests pyyaml python-owasp-zap-v2.4 \
    && printf '#!/bin/sh\nexec /usr/local/bin/python /zap/zap-baseline.py "$@"\n' > /usr/local/bin/zap-baseline.py \
    && chmod 755 /usr/local/bin/zap-baseline.py \
    && chown -R websentinel:websentinel /opt/venv /zap

USER websentinel
RUN nuclei -update-templates

WORKDIR /app
COPY --chown=websentinel:websentinel app ./app
COPY --chown=websentinel:websentinel README.md ROADMAP.md ./
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
