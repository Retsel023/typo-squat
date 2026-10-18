# Optional client only. Build separately from the scanner's large tool image.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10002 typo-tor \
    && useradd --uid 10002 --gid typo-tor --home-dir /var/lib/tor --no-create-home typo-tor \
    && mkdir -p /var/lib/tor \
    && chown 10002:10002 /var/lib/tor \
    && chmod 700 /var/lib/tor
COPY torrc /etc/tor/torrc
COPY healthcheck.py /usr/local/lib/tor-healthcheck.py
USER 10002:10002
VOLUME ["/var/lib/tor"]
EXPOSE 9050
HEALTHCHECK --interval=15s --timeout=5s --start-period=180s --retries=4 \
    CMD ["python", "/usr/local/lib/tor-healthcheck.py"]
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
