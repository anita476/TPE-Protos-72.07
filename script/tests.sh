#!/bin/bash
echo 'Compilation...'
make clean
make test
echo 'Tests...'
./bin/buffer_test
./bin/parser_test
./bin/parser_utils_test
./bin/selector_test
./bin/stm_test
echo 'All done.'