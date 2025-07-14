#!/bin/bash

NUM_CONNECTIONS=2000

URLS=(
    "http://google.com"
    "http://github.com"
    "http://example.org"
    "http://wikipedia.org"
    "http://stackoverflow.com"
    "http://bing.com"
    "http://duckduckgo.com"
    "http://reddit.com"
    "http://yahoo.com"
    "http://amazon.com"
)
success=0
fail=0

# Directory for temporary error logs
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

for ((i=0; i<NUM_CONNECTIONS; i++)); do
    url="${URLS[$((i % ${#URLS[@]}))]}"
    echo "Launching request $((i+1)) to $url"
    # Redirect stderr to a unique file for each curl
    curl --socks5-hostname localhost:1080 "$url" > /dev/null 2> "$TMPDIR/curl_err_$i" &
    pids[$i]=$!
done

for i in "${!pids[@]}"; do
    pid=${pids[$i]}
    if wait $pid; then
        ((success++))
    else
        ((fail++))
        echo "Failed with PID $pid (Request $((i+1)) to ${URLS[$((i % ${#URLS[@]}))]})"
        echo "Curl error output:"
        cat "$TMPDIR/curl_err_$i"
        echo "-----------------------------"
    fi
done

echo "All $NUM_CONNECTIONS concurrent requests completed WITH PROXY."
echo "Successful connections: $success"
echo "Failed connections: $fail"