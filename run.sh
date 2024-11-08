#!/usr/bin/env bash

set -x
set -e

if [ ! -e contrib/devtools/reg-settings.py ]; then
  git checkout setting-export^ contrib/devtools/reg-settings.py
  git commit -m 'restore reg-settings.py'
fi
git diff setting-export^ ':!run.sh' ':!test.sh' ':!contrib/devtools/reg-settings.py' ':!src/common/setting.h' ':!src/common/setting_internal.h' ':!src/test/setting_tests.cpp' | git apply -R || true
python contrib/devtools/reg-settings.py
git add -N src/bench/bench_bitcoin_settings.h src/bitcoin-tx_settings.h src/bitcoin-util_settings.h src/bitcoin-wallet_settings.h src/chainparamsbase_settings.h src/common/args_settings.h src/init/common_settings.h src/init_settings.h src/qt/bitcoin_settings.h src/test/argsman_tests_settings.h src/test/logging_tests_settings.h src/wallet/init_settings.h
