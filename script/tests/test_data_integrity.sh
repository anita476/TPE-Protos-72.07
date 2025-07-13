#!/bin/bash
# Enhanced data integrity test with size progression

set -e

# CONFIGURATION
PROXY=localhost:1080
HTTP_PORT=8082
TMP_DIR="/tmp/socks5_bigfile_test"

mkdir -p "$TMP_DIR"

# Function to test a specific file size
test_file_size() {
    local size_mb=$1
    local test_name="$2"
    
    echo ""
    echo "=== Testing $test_name (${size_mb}MB) ==="
    
    local bigfile="$TMP_DIR/testfile_${size_mb}mb.bin"
    local downloaded_file="$TMP_DIR/downloaded_${size_mb}mb.bin"
    
    # Create test file
    if [ ! -f "$bigfile" ]; then
        echo "Creating ${size_mb}MB file..."
        if [ $size_mb -le 10 ]; then
            # Use /dev/urandom for small files for integrity checking
            dd if=/dev/urandom of="$bigfile" bs=1M count="$size_mb" 2>/dev/null
        else
            # Use /dev/zero for large files (faster)
            dd if=/dev/zero of="$bigfile" bs=1M count="$size_mb" 2>/dev/null
        fi
    fi
    
    # Start HTTP server
    cd "$TMP_DIR"
    python3 -m http.server $HTTP_PORT > "http_server_${size_mb}.log" 2>&1 &
    local http_pid=$!
    sleep 1
    
    # Download with detailed progress and timeout
    echo "Downloading through SOCKS5 proxy..."
    local start_time=$(date +%s)
    
    timeout 120 curl --socks5-hostname $PROXY \
        "http://localhost:$HTTP_PORT/$(basename "$bigfile")" \
        -o "$downloaded_file" \
        --progress-bar \
        --fail-early \
        -w "Speed: %{speed_download} bytes/sec\nTime: %{time_total}s\nSize: %{size_download} bytes\n"
    
    local curl_status=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Stop HTTP server
    if kill -0 $http_pid 2>/dev/null; then
        kill $http_pid
        wait $http_pid 2>/dev/null
    fi
    
    # Analyze results
    if [ $curl_status -eq 0 ]; then
        local orig_size=$(stat -c%s "$bigfile")
        local down_size=$(stat -c%s "$downloaded_file" 2>/dev/null || echo "0")
        
        if [ "$orig_size" -eq "$down_size" ]; then
            echo "✅ SUCCESS: Complete transfer ($down_size bytes) in ${duration}s"
            
            # Verify integrity for smaller files
            if [ $size_mb -le 10 ]; then
                local orig_hash=$(sha256sum "$bigfile" | awk '{print $1}')
                local down_hash=$(sha256sum "$downloaded_file" | awk '{print $1}')
                
                if [ "$orig_hash" = "$down_hash" ]; then
                    echo "✅ INTEGRITY: Hashes match - data integrity verified"
                else
                    echo "❌ INTEGRITY: Hash mismatch detected!"
                    echo "   Original:   $orig_hash"
                    echo "   Downloaded: $down_hash"
                    return 3
                fi
            else
                echo "ℹ️  INTEGRITY: Skipped hash check for large file"
            fi
        else
            echo "❌ PARTIAL: Incomplete transfer"
            echo "   Expected: $orig_size bytes"
            echo "   Got:      $down_size bytes"
            echo "   Missing:  $((orig_size - down_size)) bytes"
            return 2
        fi
    else
        local down_size=$(stat -c%s "$downloaded_file" 2>/dev/null || echo "0")
        echo "❌ FAILED: curl exit code $curl_status in ${duration}s"
        if [ "$down_size" -gt 0 ]; then
            echo "   Partial download: $down_size bytes"
        fi
        
        # Special handling for different curl error codes
        case $curl_status in
            6)  echo "   Error: Can't resolve hostname/connect" ;;
            7)  echo "   Error: Failed to connect to host" ;;
            18) echo "   Error: Partial transfer - connection closed" ;;
            28) echo "   Error: Timeout reached" ;;
            97) echo "   Error: SOCKS5 connection failed" ;;
        esac
        
        return $curl_status
    fi
    
    return 0
}

echo "=== SOCKS5 Progressive Size Testing ==="
echo "Testing different file sizes to identify reliability patterns..."

# Progressive testing - start small and increase
declare -a test_results
test_sizes=(1 5 10 25 50 75 100)
test_names=("Small" "Medium-Small" "Medium" "Medium-Large" "Large" "Very Large" "Extra Large")

for i in "${!test_sizes[@]}"; do
    size=${test_sizes[$i]}
    name=${test_names[$i]}
    
    # Run test
    if test_file_size $size "$name"; then
        test_results[$i]="PASS"
        echo "Result: PASSED"
    else
        test_results[$i]="FAIL"
        echo "Result: FAILED"
        
        # If we start failing, test a few more times to see if it's random
        if [ $i -gt 0 ] && [ "${test_results[$((i-1))]}" = "PASS" ]; then
            echo ""
            echo "=== Detected failure point - testing reliability ==="
            local pass_count=0
            local total_attempts=3
            
            for attempt in $(seq 1 $total_attempts); do
                echo "Retry attempt $attempt/$total_attempts for ${size}MB..."
                if test_file_size $size "Retry $attempt"; then
                    ((pass_count++))
                fi
            done
            
            echo "Reliability at ${size}MB: $pass_count/$total_attempts successes"
            
            # If less than 50% success rate, don't test larger sizes
            if [ $pass_count -lt 2 ]; then
                echo "Low success rate detected - stopping size progression"
                break
            fi
        fi
    fi
done

echo ""
echo "=== Final Summary ==="
echo "Size progression results:"
for i in "${!test_sizes[@]}"; do
    if [ -n "${test_results[$i]}" ]; then
        printf "%3dMB: %s\n" "${test_sizes[$i]}" "${test_results[$i]}"
    fi
done

# Determine the likely issue
echo ""
echo "=== Analysis ==="
fail_count=0
for result in "${test_results[@]}"; do
    if [ "$result" = "FAIL" ]; then
        ((fail_count++))
    fi
done

if [ $fail_count -eq 0 ]; then
    echo "✅ All tests passed - proxy appears to be working correctly"
elif [ $fail_count -eq ${#test_results[@]} ]; then
    echo "❌ All tests failed - fundamental proxy issue"
else
    echo "⚠️  Mixed results detected - likely size-dependent or race condition issue"
    echo "   This suggests buffer management or connection timeout problems"
fi

# Clean up
echo ""
echo "Cleaning up test files..."
rm -rf "$TMP_DIR"

echo "Test complete."