#!/bin/bash
# Serve a large file locally and verify integrity through SOCKS5 proxy

set -e

# CONFIGURATION
FILE_SIZE_MB=100
BIGFILE="/tmp/bigfile.bin"
HTTP_PORT=8082
PROXY=localhost:1080
TMP_DIR="/tmp/socks5_bigfile_test"
DOWNLOADED_FILE="$TMP_DIR/bigfile_downloaded.bin"

# Create a large file with random data if it doesn't exist
if [ ! -f "$BIGFILE" ]; then
    echo "Creating $FILE_SIZE_MB MB file at $BIGFILE..."
    dd if=/dev/urandom of="$BIGFILE" bs=1M count="$FILE_SIZE_MB" status=progress
fi

mkdir -p "$TMP_DIR"

# Start HTTP server in the background
cd /tmp
python3 -m http.server $HTTP_PORT > "$TMP_DIR/http_server.log" 2>&1 &
HTTP_PID=$!
sleep 10  # Give the server time to start

trap "kill $HTTP_PID 2>/dev/null || true" EXIT


# Download the file through the SOCKS5 proxy
curl -v --socks5 $PROXY "http://localhost:$HTTP_PORT/$(basename "$BIGFILE")" -o "$DOWNLOADED_FILE" \
 -w "\nDNS: %{time_namelookup}\nConnect: %{time_connect}\nStartTransfer: %{time_starttransfer}\nTotal: %{time_total}\n"
CURL_STATUS=$?

# now without proxy
#curl -v "http://localhost:$HTTP_PORT/$(basename "$BIGFILE")" -o "$DOWNLOADED_FILE" \
#  -w "\nDNS: %{time_namelookup}\nConnect: %{time_connect}\nStartTransfer: %{time_starttransfer}\nTotal: %{time_total}\n"

# Stop the HTTP server if still running
if kill -0 $HTTP_PID 2>/dev/null; then
    kill $HTTP_PID
    wait $HTTP_PID 2>/dev/null
fi

# Check download status
if [ $CURL_STATUS -ne 0 ]; then
    echo "curl failed with status $CURL_STATUS"
    exit 2
fi

# Compare SHA256 hashes
ORIG_HASH=$(sha256sum "$BIGFILE" | awk '{print $1}')
DOWN_HASH=$(sha256sum "$DOWNLOADED_FILE" | awk '{print $1}')

if [ "$ORIG_HASH" = "$DOWN_HASH" ]; then
    echo "SUCCESS: Hashes match. Data integrity verified"
    rm -rf "$TMP_DIR"
    exit 0
else
    echo "FAILURE: Hashes differ! Data integrity compromised"
    echo "Original:   $ORIG_HASH"
    echo "Downloaded: $DOWN_HASH"
    exit 3
fi