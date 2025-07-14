#!/bin/bash
# Concurrent stress test for SOCKS5 proxy
# Runs test_data_integrity1.sh multiple times in parallel

# Made by cursor in a pinch .... wouldnt trust it too much but will revise later :p
set -e

# CONFIGURATION
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SCRIPT="$SCRIPT_DIR/test_data_integrity1.sh"
RESULTS_DIR="/tmp/socks5_stress_test_$(date +%Y%m%d_%H%M%S)"
LOG_DIR="$RESULTS_DIR/logs"
SUMMARY_FILE="$RESULTS_DIR/summary.txt"

# Test parameters
CONCURRENT_RUNS=${1:-10}  
MAX_RUNTIME=${2:-300}     # Default to 5 minutes max runtime
DELAY_BETWEEN_STARTS=${3:-2}  # Seconds between starting each test

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%H:%M:%S')] $message${NC}"
}

# Function to check if test script exists
check_test_script() {
    if [ ! -f "$TEST_SCRIPT" ]; then
        print_status $RED "Error: Test script not found at $TEST_SCRIPT"
        exit 1
    fi
    
    if [ ! -x "$TEST_SCRIPT" ]; then
        print_status $YELLOW "Making test script executable..."
        chmod +x "$TEST_SCRIPT"
    fi
}

# Function to create results directory
setup_results_dir() {
    mkdir -p "$LOG_DIR"
    print_status $BLUE "Results will be saved to: $RESULTS_DIR"
}

# Function to run a single test instance
run_single_test() {
    local test_id=$1
    local log_file="$LOG_DIR/test_${test_id}.log"
    local start_time=$(date +%s)
    
    print_status $BLUE "Starting test instance $test_id..."
    
    # Run the test with timeout
    timeout $MAX_RUNTIME "$TEST_SCRIPT" > "$log_file" 2>&1
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Analyze results
    if [ $exit_code -eq 0 ]; then
        print_status $GREEN "Test $test_id completed successfully in ${duration}s"
        echo "PASS,$test_id,$duration,$start_time,$end_time" >> "$SUMMARY_FILE"
    elif [ $exit_code -eq 124 ]; then
        print_status $RED "Test $test_id timed out after ${duration}s"
        echo "TIMEOUT,$test_id,$duration,$start_time,$end_time" >> "$SUMMARY_FILE"
    else
        print_status $RED "Test $test_id failed with exit code $exit_code in ${duration}s"
        echo "FAIL,$test_id,$duration,$start_time,$end_time" >> "$SUMMARY_FILE"
    fi
    
    return $exit_code
}

# Function to run all tests concurrently
run_concurrent_tests() {
    
    local pids=()
    local test_id=1
    
    print_status $BLUE "Starting $CONCURRENT_RUNS concurrent test instances..."
    print_status $BLUE "Each test will timeout after ${MAX_RUNTIME}s"
    print_status $BLUE "Starting tests with ${DELAY_BETWEEN_STARTS}s delay between each..."
    
    # Start all test instances
    for ((i=1; i<=CONCURRENT_RUNS; i++)); do
        run_single_test $i &
        pids+=($!)
        
        # Small delay between starting tests to avoid overwhelming the system
        if [ $i -lt $CONCURRENT_RUNS ]; then
            sleep $DELAY_BETWEEN_STARTS
        fi
    done
    
    print_status $BLUE "All $CONCURRENT_RUNS tests started. Waiting for completion..."
    
    # Wait for all tests to complete
    local completed=0
    local passed=0
    local failed=0
    local timed_out=0
    
    for pid in "${pids[@]}"; do
        if wait $pid; then
            ((passed++))
        else
            local exit_code=$?
            if [ $exit_code -eq 124 ]; then
                ((timed_out++))
            else
                ((failed++))
            fi
        fi
        ((completed++))
        print_status $BLUE "Progress: $completed/$CONCURRENT_RUNS tests completed"
    done
    
    # Print final results
    print_status $GREEN "All tests completed!"
    print_status $GREEN "Results: $passed passed, $failed failed, $timed_out timed out"
}

# Function to generate summary report
generate_summary() {
    print_status $BLUE "Generating summary report..."
    
    echo "=== SOCKS5 Concurrent Stress Test Summary ===" > "$SUMMARY_FILE"
    echo "Date: $(date)" >> "$SUMMARY_FILE"
    echo "Concurrent runs: $CONCURRENT_RUNS" >> "$SUMMARY_FILE"
    echo "Max runtime per test: ${MAX_RUNTIME}s" >> "$SUMMARY_FILE"
    echo "Delay between starts: ${DELAY_BETWEEN_STARTS}s" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    
    # Count results
    local total_passed=$(grep -c "^PASS," "$SUMMARY_FILE" 2>/dev/null || echo "0")
    local total_failed=$(grep -c "^FAIL," "$SUMMARY_FILE" 2>/dev/null || echo "0")
    local total_timeout=$(grep -c "^TIMEOUT," "$SUMMARY_FILE" 2>/dev/null || echo "0")
    
    echo "=== Final Results ===" >> "$SUMMARY_FILE"
    echo "Total tests: $CONCURRENT_RUNS" >> "$SUMMARY_FILE"
    echo "Passed: $total_passed" >> "$SUMMARY_FILE"
    echo "Failed: $total_failed" >> "$SUMMARY_FILE"
    echo "Timed out: $total_timeout" >> "$SUMMARY_FILE"
    echo "Success rate: $(( (total_passed * 100) / CONCURRENT_RUNS ))%" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    
    # Calculate average duration
    if [ $total_passed -gt 0 ]; then
        local avg_duration=$(awk -F',' '/^PASS,/ {sum+=$3; count++} END {if(count>0) print sum/count; else print 0}' "$SUMMARY_FILE")
        echo "Average duration (passed tests): ${avg_duration}s" >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "=== Detailed Results ===" >> "$SUMMARY_FILE"
    echo "Status,TestID,Duration(s),StartTime,EndTime" >> "$SUMMARY_FILE"
    
    # Sort by test ID for better readability
    grep -E "^(PASS|FAIL|TIMEOUT)," "$SUMMARY_FILE" | sort -t',' -k2 -n >> "$SUMMARY_FILE"
    
    print_status $GREEN "Summary saved to: $SUMMARY_FILE"
}

# Function to analyze logs for common issues
analyze_logs() {
    print_status $BLUE "Analyzing logs for common issues..."
    
    local analysis_file="$RESULTS_DIR/analysis.txt"
    echo "=== Log Analysis ===" > "$analysis_file"
    echo "Date: $(date)" >> "$analysis_file"
    echo "" >> "$analysis_file"
    
    # Count different types of errors
    local connection_errors=$(grep -r "Failed to connect\|Can't resolve hostname" "$LOG_DIR" | wc -l)
    local timeout_errors=$(grep -r "transfer closed with.*bytes remaining\|timeout" "$LOG_DIR" | wc -l)
    local hash_mismatches=$(grep -r "Hash mismatch\|INTEGRITY.*FAIL" "$LOG_DIR" | wc -l)
    local partial_transfers=$(grep -r "Partial transfer\|Incomplete transfer" "$LOG_DIR" | wc -l)
    
    echo "=== Error Summary ===" >> "$analysis_file"
    echo "Connection errors: $connection_errors" >> "$analysis_file"
    echo "Timeout/transfer errors: $timeout_errors" >> "$analysis_file"
    echo "Hash mismatches: $hash_mismatches" >> "$analysis_file"
    echo "Partial transfers: $partial_transfers" >> "$analysis_file"
    echo "" >> "$analysis_file"
    
    # Show sample error messages
    if [ $timeout_errors -gt 0 ]; then
        echo "=== Sample Timeout Errors ===" >> "$analysis_file"
        grep -r "transfer closed with.*bytes remaining" "$LOG_DIR" | head -5 >> "$analysis_file"
        echo "" >> "$analysis_file"
    fi
    
    if [ $hash_mismatches -gt 0 ]; then
        echo "=== Sample Hash Mismatches ===" >> "$analysis_file"
        grep -r "Hash mismatch\|INTEGRITY.*FAIL" "$LOG_DIR" | head -5 >> "$analysis_file"
        echo "" >> "$analysis_file"
    fi
    
    print_status $GREEN "Analysis saved to: $analysis_file"
}

# Function to cleanup on exit
cleanup() {
    print_status $YELLOW "Cleaning up..."
    # Kill any remaining background processes
    jobs -p | xargs -r kill
}

# Main execution
main() {
    # Set up cleanup trap
    trap cleanup EXIT
    
    print_status $BLUE "=== SOCKS5 Concurrent Stress Test ==="
    print_status $BLUE "Concurrent runs: $CONCURRENT_RUNS"
    print_status $BLUE "Max runtime per test: ${MAX_RUNTIME}s"
    print_status $BLUE "Delay between starts: ${DELAY_BETWEEN_STARTS}s"
    echo
    
    # Pre-flight checks
    check_test_script
    setup_results_dir
    
    # Initialize summary file
    echo "Status,TestID,Duration,StartTime,EndTime" > "$SUMMARY_FILE"
    
    # Run the tests
    local start_time=$(date +%s)
    run_concurrent_tests
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    # Generate reports
    generate_summary
    analyze_logs
    
    # Final summary
    print_status $GREEN "=== Test Complete ==="
    print_status $GREEN "Total test duration: ${total_duration}s"
    print_status $GREEN "Results directory: $RESULTS_DIR"
    print_status $GREEN "Summary: $SUMMARY_FILE"
    
    # Show quick results
    local total_passed=$(grep -c "^PASS," "$SUMMARY_FILE" 2>/dev/null || echo "0")
    local success_rate=$(( (total_passed * 100) / CONCURRENT_RUNS ))
    
    if [ $success_rate -ge 90 ]; then
        print_status $GREEN "Excellent reliability: ${success_rate}% success rate"
    elif [ $success_rate -ge 75 ]; then
        print_status $YELLOW "Good reliability: ${success_rate}% success rate"
    else
        print_status $RED "Poor reliability: ${success_rate}% success rate - investigate issues"
    fi
}

# Show usage if requested
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 [concurrent_runs] [max_runtime_seconds] [delay_between_starts]"
    echo ""
    echo "Parameters:"
    echo "  concurrent_runs        Number of tests to run in parallel (default: 10)"
    echo "  max_runtime_seconds    Maximum runtime per test in seconds (default: 300)"
    echo "  delay_between_starts   Seconds to wait between starting each test (default: 2)"
    echo ""
    exit 0
fi

# Run main function
main "$@" 