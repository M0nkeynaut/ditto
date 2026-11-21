#!/bin/sh
# Download the free DB-IP "IP to Country Lite" database (CC BY 4.0) to
# geoip/country.mmdb so the collector can show attacker countries.
# Optional - DITTO works without it (countries just show as unknown).
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)/geoip"
mkdir -p "$DIR"
for m in "$(date +%Y-%m)" "$(date -d '-1 month' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m)"; do
  url="https://download.db-ip.com/free/dbip-country-lite-$m.mmdb.gz"
  echo "trying $url"
  if curl -fsSL -o "$DIR/country.mmdb.gz" "$url"; then
    gunzip -f "$DIR/country.mmdb.gz"
    echo "installed $DIR/country.mmdb ($m)"
    exit 0
  fi
done
echo "download failed - DITTO will run without country lookups" >&2
exit 1
