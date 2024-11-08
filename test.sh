#!/usr/bin/env bash

run() {
  echo -n "=== "
  sys-quote "$@"
  "$@"
  ret=$?
  if [ "$ret" -eq 0 ]; then
    echo -n "=== Success: "
  else
    echo -n "=== Failure $ret: "
  fi
  sys-quote "$@"
  return "$ret"
}

if run make -C build/src/test setting_tests.cpp.o; then
  if run make -j8 -C build/src/test test_bitcoin; then
    run ctest --test-dir build -V -R setting_tests
  fi
fi

if run make -j8 -C build bitcoind; then
  run build/test/functional/feature_asmap.py
  run build/test/functional/feature_settings.py
  run build/test/functional/feature_logging.py
  if run make -j8 -C build bitcoin-wallet; then
    run build/test/functional/tool_wallet.py
  fi
fi

if run make -j8 -C build bitcoind test_bitcoin bitcoin-wallet bitcoin-cli bitcoin-tx bitcoin-util; then
  run ctest --test-dir build -E '^tests$' -j12
  run build/test/functional/test_runner.py
fi
