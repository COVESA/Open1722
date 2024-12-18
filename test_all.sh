#!/bin/bash
set -ev

rm -rf build
mkdir build
cd build
cmake ..
make -j`nproc`
make unittests
make test

lcov -c -d . -o main_coverage.info
genhtml main_coverage.info -o ./coverage/