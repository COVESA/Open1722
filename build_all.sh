#!/bin/bash 
set -ev 

rm -rf build
mkdir build
cd build
cmake -DOPEN1722_BUILD_TESTS=ON -DOPEN1722_BUILD_EXAMPLES=ON ..
make -j`nproc`
