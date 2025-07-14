#!/bin/bash

PROXY_HOST="localhost"
PROXY_PORT=1080
TARGET_HOST="httpbin.org"
TARGET_PORT=80
NUM_CONNECTIONS=1000

echo "Creating $NUM_CONNECTIONS sustained netcat connections..."

for i in $(seq 1 $NUM_CONNECTIONS); do
    (
        # send SOCKS5 handshake
        echo -en "\x05\x01\x00"
        # send SOCKS5 connect request
        echo -en "\x05\x01\x00\x03"
        echo -en "\x0chttpbin.org"
        echo -en "\x00\x50"
        sleep 5
    ) | ncat $PROXY_HOST $PROXY_PORT > /dev/null 2>&1 &
    
    if [ $((i % 50)) -eq 0 ]; then
        echo "Created $i connections..."
    fi
done

echo "All connections created. Monitoring for 30 seconds..."
sleep 30

echo "Test complete. Cleaning up..."
wait