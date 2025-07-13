#!/bin/bash

# Number of concurrent connections to test
NUM_CONNECTIONS=2000

# Array of URLs to test
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

# Launch concurrent curl requests
for ((i=0; i<NUM_CONNECTIONS; i++)); do
    url="${URLS[$((i % ${#URLS[@]}))]}"
    echo "Launching request $((i+1)) to $url"
    curl --max-time 10 "$url" > /dev/null 2>&1 &
    pids[$i]=$!
done

# Wait for all background curl processes
for pid in "${pids[@]}"; do
    if wait $pid; then
        ((success++))
    else
        ((fail++))
        echo "Failed with PID $pid"
    fi
done

echo "All $NUM_CONNECTIONS concurrent requests completed WITHOUT PROXY."
echo "Successful connections: $success"
echo "Failed connections: $fail"
