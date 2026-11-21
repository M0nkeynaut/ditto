#!/bin/sh
# DITTO bare-metal / LXC installer for Debian or Ubuntu. Run as root.
#
# This sets up the TARPIT (endlessh), the COLLECTOR and the DASHBOARD via
# systemd. It does NOT install Cowrie - see the README for the honeypot
# (Docker is the easiest way to run Cowrie; point the collector at its logs).
#
# Vibe-coded. Read it before running it.
set -e
[ "$(id -u)" = "0" ] || { echo "run as root"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/ditto

echo "== installing packages =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y --no-install-recommends \
  python3 python3-pyelftools python3-ssdeep python3-maxminddb \
  binutils file endlessh curl

echo "== copying DITTO to $DEST =="
mkdir -p "$DEST" "$DEST/web/data"
cp -r "$SRC/collector" "$SRC/web" "$DEST/"
mkdir -p "$DEST/web/data"

echo "== endlessh tarpit on port 2222 =="
install -m 644 "$SRC/endlessh/config" /etc/endlessh/config
systemctl enable --now endlessh 2>/dev/null || systemctl restart endlessh || true

echo "== collector config =="
mkdir -p /etc/ditto
if [ ! -f /etc/ditto/ditto.env ]; then
  cat > /etc/ditto/ditto.env <<EOF
# Point these at your Cowrie installation:
COWRIE_LOG_DIR=/srv/cowrie/var/log/cowrie
COWRIE_DL_DIR=/srv/cowrie/var/lib/cowrie/downloads
# endlessh: read the systemd journal of the endlessh unit...
ENDLESSH_UNIT=endlessh
# ...or a log file instead (leave ENDLESSH_UNIT empty then):
# ENDLESSH_LOG=/var/log/endlessh/endlessh.log
# Optional country database (run scripts/fetch-geoip.sh):
GEOIP_DB=$DEST/geoip/country.mmdb
# Where the dashboard JSON is written (keep the trailing /data):
DITTO_DATA=$DEST/web/data
# Dashboard port for ditto-web.service:
DITTO_PORT=8080
DITTO_LOOKBACK_DAYS=7
EOF
  echo "  wrote /etc/ditto/ditto.env - EDIT the COWRIE_* paths!"
fi

echo "== systemd units =="
install -m 644 "$SRC/systemd/ditto-collector.service" /etc/systemd/system/
install -m 644 "$SRC/systemd/ditto-collector.timer" /etc/systemd/system/
install -m 644 "$SRC/systemd/ditto-web.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ditto-collector.timer
systemctl enable --now ditto-web.service

cat <<EOF

DITTO installed.
  1. Install Cowrie and set COWRIE_LOG_DIR / COWRIE_DL_DIR in /etc/ditto/ditto.env
  2. (optional) sh scripts/fetch-geoip.sh for attacker countries
  3. systemctl start ditto-collector.service   # first run
  4. open http://<this-host>:8080/

Read the Security section of the README before exposing anything.
EOF
