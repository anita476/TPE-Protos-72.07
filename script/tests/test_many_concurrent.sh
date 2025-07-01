#!/bin/bash

# Number of concurrent connections to test
NUM_CONNECTIONS=500

# Array of URLs to test (add more if you want)
URLS=(
    "http://google.com"
    "http://github.com"
    "http://example.com"
    "http://wikipedia.org"
    "http://stackoverflow.com"
    "http://bing.com"
    "http://duckduckgo.com"
    "http://reddit.com"
    "http://yahoo.com"
    "http://amazon.com"
)

# Launch concurrent curl requests
for ((i=0; i<NUM_CONNECTIONS; i++)); do
    # Pick a URL from the list (cycling through if NUM_CONNECTIONS > number of URLs)
    url="${URLS[$((i % ${#URLS[@]}))]}"
    echo "Launching request $((i+1)) to $url"
    curl --socks5-hostname localhost:1080 "$url" &
done

# Wait for all background jobs to finish
wait

echo "All $NUM_CONNECTIONS concurrent requests completed."