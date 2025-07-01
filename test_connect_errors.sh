# 1. Test successful DNS resolution and connection
curl --socks5-hostname localhost:1080 http://httpbin.org/ip

# 2. Test direct IP (no DNS needed)
curl --socks5 localhost:1080 http://8.8.8.8

# 3. Test invalid domain (should fail gracefully)
curl --socks5-hostname localhost:1080 http://thisdomaindoesnotexist12345.com

# 4. Test connection refused (valid domain, invalid port)
curl --socks5-hostname localhost:1080 http://google.com:12345 # it hangs indefinitely in the second address resolution bc of EINPROGRESS

# 5. Test concurrent connections
curl --socks5-hostname localhost:1080 http://google.com &
curl --socks5-hostname localhost:1080 http://github.com &
wait

curl --socks5 localhost:1080 http://127.0.0.1:9999 # should return CONNECTION REFUSED quickly-- no server running on this port