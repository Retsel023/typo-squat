# syntax=docker/dockerfile:1
# Subfinder v2.17.0 requires Go 1.26. Build a static binary separately so the
# application image does not need Go, Kali, cron, or the legacy installers.
FROM golang:1.26.9-bookworm AS tools
ARG SUBFINDER_VERSION=v2.17.0
ENV GOTOOLCHAIN=local
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

# This release includes its built report assets. Pin the commit as well as tag.
ARG GOWITNESS_REVISION=601c84367aaf26eae7d1b5181b70633cb662cf66
RUN git clone --depth 1 --branch 3.2.2 https://github.com/sensepost/gowitness.git /src/gowitness \
    && git -C /src/gowitness checkout --detach ${GOWITNESS_REVISION} \
    && cd /src/gowitness \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gowitness .

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/data \
    XDG_CONFIG_HOME=/data/config \
    XDG_CACHE_HOME=/data/cache
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium fonts-liberation ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --home-dir /data --no-create-home app \
    && mkdir /data \
    && chown app:app /data

COPY --from=tools /out/subfinder /usr/local/bin/subfinder
COPY --from=tools /out/gowitness /usr/local/bin/gowitness
COPY typo_monitor ./typo_monitor

USER 10001:10001
VOLUME ["/data"]
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).read()"]
CMD ["python", "-m", "typo_monitor", "--data-dir", "/data", "--chrome-path", "/usr/bin/chromium", "serve", "--host", "0.0.0.0", "--port", "5000"]
