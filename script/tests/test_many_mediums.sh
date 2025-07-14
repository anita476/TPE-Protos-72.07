#!/bin/bash

NUM_RUNS=600

for ((i=1; i<=NUM_RUNS; i++)); do
  echo "Launching test_medium_file.sh instance $i"
  ./script/tests/test_medium_file.sh > "medium_out_$i.log" 2>&1 &
  pids[$i]=$!
done

for pid in "${pids[@]}"; do
  wait $pid
done

echo "All $NUM_RUNS concurrent test_medium_file.sh runs completed."