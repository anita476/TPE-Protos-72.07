#!/bin/bash
echo 'Compilation...'
make clean
make test
echo 'Tests...'
./bin/buffer_test
./bin/selector_test
./bin/netutils_test
echo 'All done.'