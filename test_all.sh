#!/bin/bash
set -ev

rm -rf build
mkdir build
cd build
cmake .. -DUNIT_TESTING=on
make -j`nproc`
make test

lcov -c -d . -o main_coverage.info
genhtml main_coverage.info -o ./coverage/