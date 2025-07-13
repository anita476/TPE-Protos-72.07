# Then run the profiling 
strace -c -f ./bin/socks5d -s & PROXY_PID=$! 
# Run your test 
./script/tests/test_netcat_many.sh 
# Stop and see results 
kill $PROXY_PID