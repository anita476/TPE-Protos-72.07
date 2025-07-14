#!/bin/bash

# IPv6 SOCKS5 Proxy Test Script

PROXY="localhost:1080"
TEST_SERVER_PORT="8080"

echo "=== IPv6 SOCKS5 Proxy Tests ==="
echo "Proxy: $PROXY"
echo "Test server: localhost:$TEST_SERVER_PORT"
echo

# Function to run test with timeout and error handling
run_test() {
    local test_name="$1"
    local curl_cmd="$2"
    
    echo -n "Testing $test_name... "
    
    if timeout 10s $curl_cmd > /dev/null 2>&1; then
        echo "✓ PASS"
        return 0
    else
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "✗ TIMEOUT"
        else
            echo "✗ FAIL (exit code: $exit_code)"
        fi
        return 1
    fi
}

# Test 1: IPv6 loopback direct
run_test "IPv6 loopback [::1]" \
    "curl --socks5-hostname $PROXY 'http://[::1]:$TEST_SERVER_PORT/'"

# Test 2: IPv6 with --socks5 (client resolves)
run_test "IPv6 with --socks5" \
    "curl --socks5 $PROXY 'http://[::1]:$TEST_SERVER_PORT/'"

# Test 3: IPv6-only hostname (if available)
run_test "IPv6 hostname resolution" \
    "curl --socks5-hostname $PROXY 'http://ipv6.google.com/'"

# Test 4: Force IPv6 resolution for dual-stack hostname
run_test "Force IPv6 for google.com" \
    "curl -6 --socks5-hostname $PROXY 'http://google.com/'"

# Test 5: Mixed - IPv4 proxy to IPv6 destination
run_test "IPv4 proxy to IPv6 destination" \
    "curl --socks5-hostname 127.0.0.1:1080 'http://[::1]:$TEST_SERVER_PORT/'"

echo
echo "=== Detailed IPv6 Test (with output) ==="

# Detailed test with full output
echo "Running detailed IPv6 test..."
curl -v --socks5-hostname $PROXY "http://[::1]:$TEST_SERVER_PORT/" 2>&1 | \
    grep -E "(SOCKS|IPv6|Connected|trying)"

echo
echo "=== IPv6 Connectivity Check ==="

# Check if IPv6 is available on the system
if ip -6 addr show lo | grep -q "::1"; then
    echo "✓ IPv6 loopback available"
else
    echo "✗ IPv6 loopback not available"
fi

# Check if test server is listening on IPv6
if netstat -tlnp 2>/dev/null | grep -q "::.*:$TEST_SERVER_PORT"; then
    echo "✓ Test server listening on IPv6"
elif netstat -tlnp 2>/dev/null | grep -q ".*:$TEST_SERVER_PORT"; then
    echo "⚠ Test server listening on IPv4 only"
else
    echo "✗ Test server not found on port $TEST_SERVER_PORT"
fi

echo
echo "=== Advanced IPv6 Tests ==="

# Test with different IPv6 formats
run_test "Compressed IPv6 [::1]" \
    "curl --socks5-hostname $PROXY 'http://[::1]:$TEST_SERVER_PORT/'"

run_test "Full IPv6 [0000:0000:0000:0000:0000:0000:0000:0001]" \
    "curl --socks5-hostname $PROXY 'http://[0000:0000:0000:0000:0000:0000:0000:0001]:$TEST_SERVER_PORT/'"

# Test data transfer over IPv6
echo
echo "=== IPv6 Data Transfer Test ==="
echo "Testing larger data transfer over IPv6..."

if timeout 30s curl --socks5-hostname $PROXY "http://[::1]:$TEST_SERVER_PORT/" \
    --data-raw "$(head -c 1024 /dev/zero | tr '\0' 'A')" \
    > /dev/null 2>&1; then
    echo "✓ IPv6 data transfer successful"
else
    echo "✗ IPv6 data transfer failed"
fi

echo
echo "=== Test Summary ==="
echo "IPv6 SOCKS5 proxy testing completed."
echo "Check your proxy logs for detailed IPv6 connection handling."