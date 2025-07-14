#!/bin/bash

## Same test without proxy, should take approx half the time
# Number of concurrent connections to test
NUM_CONNECTIONS=2000

# Array of URLs to test (add more if you want)
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
    # Pick a URL from the list (cycling through if NUM_CONNECTIONS > number of URLs)
    url="${URLS[$((i % ${#URLS[@]}))]}"
    echo "Launching request $((i+1)) to $url"
    curl "$url" > /dev/null 2>&1 &
    pids[$i]=$!
done
for pid in "${pids[@]}"; do
    if wait $pid; then
        ((success++))
    else
        ((fail++))
        echo "Failed with PID $pid"
    fi
done

# Wait for all background jobs to finish
#wait

echo "All $NUM_CONNECTIONS concurrent requests completed NO PROXY."
echo "Successful connections: $success"
echo "Failed connections: $fail"