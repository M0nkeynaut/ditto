# endlessh tarpit - built from the Debian package (logs ISO timestamps that the
# DITTO collector understands). Writes ACCEPT/CLOSE lines to a shared log file.
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends endlessh \
 && rm -rf /var/lib/apt/lists/*
COPY config /etc/endlessh/config
EXPOSE 2222
# -v prints connection diagnostics to stdout; tee keeps a copy for the collector.
ENTRYPOINT ["/bin/sh", "-c", "mkdir -p /logs && /usr/bin/endlessh -v -f /etc/endlessh/config 2>&1 | tee -a /logs/endlessh.log"]
