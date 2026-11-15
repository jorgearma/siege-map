#!/usr/bin/env bash
# Download the free DB-IP "lite" databases (city + ASN) in MaxMind .mmdb format
# for GEO_PROVIDER=mmdb. They are published monthly; run this from cron once a
# month and restart the backend:
#
#   0 4 2 * *  cd /opt/siege-map && ./scripts/fetch_geoip.sh && docker compose restart backend
#
# Licence: CC BY 4.0 — attribution to https://db-ip.com is required
# (the README credits it). MaxMind GeoLite2 files work too: name them
# city.mmdb / asn.mmdb in the same folder.
set -euo pipefail

DEST="${1:-./geoip}"
MONTH="$(date +%Y-%m)"
mkdir -p "$DEST"

fetch() {  # fetch <dbip-name> <output-name>
    local url="https://download.db-ip.com/free/dbip-$1-lite-${MONTH}.mmdb.gz"
    echo "Downloading $url"
    curl -fsSL "$url" -o "$DEST/$2.mmdb.gz.tmp"
    gunzip -c "$DEST/$2.mmdb.gz.tmp" > "$DEST/$2.mmdb.tmp"
    mv "$DEST/$2.mmdb.tmp" "$DEST/$2.mmdb"     # atomic swap: never a half file
    rm -f "$DEST/$2.mmdb.gz.tmp"
}

fetch city city
fetch asn asn
chmod 644 "$DEST"/*.mmdb
ls -lh "$DEST"/*.mmdb
echo "Done. Set GEO_PROVIDER=mmdb in .env and restart the backend."
