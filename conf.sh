#!/usr/bin/env bash

set -x
set -e

CXX=g++ cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_BENCH=ON -DBUILD_FUZZ_BINARY=ON -DBUILD_GUI=ON -DBUILD_KERNEL_LIB=ON -DBUILD_UTIL_CHAINSTATE=ON -DWERROR=ON -DWITH_BDB=ON -DWITH_MINIUPNPC=ON -DWITH_ZMQ=ON
make -C build/src bitcoind -j9 -k
make -C build -j9 -k
