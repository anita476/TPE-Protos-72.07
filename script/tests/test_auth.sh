#!/bin/bash
# test auth is working okey 
# we assume at least one user admin:admin exists!

PROXY=localhost:1080
URL=http://httpbin.org

echo "Testing correct credentials..."
curl --socks5-hostname admin:admin@$PROXY $URL -s -o /dev/null && echo "PASS" || echo "FAIL"

echo "Testing wrong password..."
curl --socks5-hostname admin:wrong@$PROXY $URL -s -o /dev/null && echo "FAIL" || echo "PASS"

echo "Testing wrong username..."
curl --socks5-hostname wrong:admin@$PROXY $URL -s -o /dev/null && echo "FAIL" || echo "PASS"

echo "Testing no credentials..."
curl --socks5-hostname $PROXY $URL -s -o /dev/null && echo "FAIL" || echo "PASS"