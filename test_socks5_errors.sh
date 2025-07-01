#!/bin/bash

# SOCKS5 Error Handling Test Script
# Tests various error conditions for your SOCKS5 server

SERVER_HOST="localhost"
SERVER_PORT="1080"

echo "=== SOCKS5 Error Handling Tests ==="
echo "Server: $SERVER_HOST:$SERVER_PORT"
echo

# Test 1: Invalid SOCKS version
echo "Test 1: Invalid SOCKS version (0x04)"
echo -ne "\x04\x01\x00" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: SOCKS5_REPLY_GENERAL_FAILURE"
echo

# Test 2: No methods
echo "Test 2: No authentication methods"
echo -ne "\x05\x00" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: SOCKS5_REPLY_GENERAL_FAILURE"
echo

# Test 3: Unsupported auth method
echo "Test 3: Unsupported authentication method (0x02)"
echo -ne "\x05\x01\x02" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: 0x05 0xFF (no acceptable methods)"
echo

# Test 4: Unsupported command (BIND)
echo "Test 4: Unsupported command (BIND)"
echo -ne "\x05\x01\x00\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: SOCKS5_REPLY_COMMAND_NOT_SUPPORTED"
echo

# Test 5: Unsupported address type
echo "Test 5: Unsupported address type (0x02)"
echo -ne "\x05\x01\x00\x05\x01\x00\x02\x7f\x00\x00\x01\x00\x50" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED"
echo

# Test 6: Invalid reserved field
echo "Test 6: Invalid reserved field (0x01)"
echo -ne "\x05\x01\x00\x05\x01\x01\x01\x7f\x00\x00\x01\x00\x50" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: SOCKS5_REPLY_GENERAL_FAILURE"
echo

# Test 7: Connection refused (port 1)
echo "Test 7: Connection refused (port 1)"
echo -ne "\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x01" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: SOCKS5_REPLY_CONNECTION_REFUSED"
echo

# Test 8: Malformed request (incomplete)
echo "Test 8: Malformed request (incomplete)"
echo -ne "\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00" | nc -w 3 $SERVER_HOST $SERVER_PORT
echo "Expected: Server should wait for more data or timeout"
echo

echo "=== Tests Complete ===" 