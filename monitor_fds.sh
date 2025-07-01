#!/bin/bash

# File Descriptor Monitoring Script
# Usage: ./monitor_fds.sh <PID> [interval_seconds]

PID=$1
INTERVAL=${2:-5}  # Default 5 seconds

if [ -z "$PID" ]; then
    echo "Usage: $0 <PID> [interval_seconds]"
    echo "Example: $0 12345 2"
    exit 1
fi

echo "Monitoring file descriptors for PID $PID every $INTERVAL seconds..."
echo "Press Ctrl+C to stop"
echo

while true; do
    if [ ! -d "/proc/$PID" ]; then
        echo "Process $PID no longer exists"
        break
    fi
    
    # Count file descriptors
    FD_COUNT=$(ls /proc/$PID/fd/ 2>/dev/null | wc -l)
    
    # Get socket information
    SOCKET_INFO=$(lsof -p $PID 2>/dev/null | grep -E "(sock|TCP|UDP)" | head -5)
    
    # Timestamp
    TIMESTAMP=$(date '+%H:%M:%S')
    
    echo "[$TIMESTAMP] PID $PID: $FD_COUNT file descriptors"
    
    if [ ! -z "$SOCKET_INFO" ]; then
        echo "Recent sockets:"
        echo "$SOCKET_INFO" | sed 's/^/  /'
    fi
    
    echo "---"
    sleep $INTERVAL
done 