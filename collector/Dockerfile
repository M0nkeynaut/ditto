# DITTO collector - reads the honeypot/tarpit logs and writes stats.json + report.json.
# All analysis tooling comes from Debian packages; nothing is built from pip.
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-pyelftools python3-ssdeep python3-maxminddb \
      binutils file ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ditto_collector.py run-loop.sh /app/
RUN chmod +x /app/run-loop.sh
ENTRYPOINT ["/app/run-loop.sh"]
