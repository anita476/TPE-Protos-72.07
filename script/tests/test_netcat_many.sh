#!/bin/bash

#PROXY_HOST="localhost"
#PROXY_PORT=1080
#TARGET_HOST="httpbin.org"
#TARGET_PORT=80
NUM_CONNECTIONS=500

echo "Creating $NUM_CONNECTIONS sustained ncat connections..."

for i in $(seq 1 $NUM_CONNECTIONS); do

    ncat --proxy localhost:1080 --proxy-type socks5 localhost 80 &
    if [ $((i % 50)) -eq 0 ]; then
        echo "Created $i connections..."
    fi
done

echo "All connections created. Monitoring for 30 seconds..."
sleep 30

echo "Test complete. Kill netcats..."
wait