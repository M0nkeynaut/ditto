#!/bin/sh
# Run the DITTO collector in a loop. Interval via DITTO_INTERVAL (seconds).
set -e
INTERVAL="${DITTO_INTERVAL:-120}"
echo "DITTO collector loop, every ${INTERVAL}s"
while true; do
  python3 /app/ditto_collector.py all || echo "collector run failed, retrying next cycle"
  sleep "$INTERVAL"
done
