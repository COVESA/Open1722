#!/bin/bash
set -ev

rm -rf build
mkdir build
cd build
cmake ..
make -j`nproc`
make examples
