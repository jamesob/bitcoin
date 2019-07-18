#!/usr/bin/env bash

# Demonstrate the creation and usage of UTXO snapshots.
#
# A server node starts up, IBDs up to a certain height, then generates a UTXO
# snapshot at that point.
#
# The server then downloads more blocks (to create a diff from the snapshot).
#
# We bring a client up, load the UTXO snapshot, and we show the client sync to
# the "network tip" and then start a background validation of the snapshot it
# loaded. We see the background validation chainstate removed after validation
# completes.
#

set -e

BASE_HEIGHT=${1:-30000}
INCREMENTAL_HEIGHT=8000
FINAL_HEIGHT=$(("$BASE_HEIGHT" + "$INCREMENTAL_HEIGHT"))

SERVER_DATADIR="$(pwd)/utxodemo-data-server-$BASE_HEIGHT"
CLIENT_DATADIR="$(pwd)/utxodemo-data-client-$BASE_HEIGHT"
UTXO_DAT_FILE="$(pwd)/utxo.$BASE_HEIGHT.dat"

finish() {
  echo "Killing server and client PIDs ($SERVER_PID, $CLIENT_PID) and cleaning up datadirs"
  rm -rf $SERVER_DATADIR $CLIENT_DATADIR $UTXO_DAT_FILE
  kill -9 $SERVER_PID $CLIENT_PID
}

trap finish EXIT

# Need to specify these to trick client into accepting server as a peer
# it can IBD from.
CHAIN_HACK_FLAGS="-maxtipage=99999999999999999999999 -minimumchainwork=0x00"

server_rpc() {
  ./src/bitcoin-cli -datadir=$SERVER_DATADIR "$@"
}
client_rpc() {
  ./src/bitcoin-cli -rpcport=9999 -datadir=$CLIENT_DATADIR "$@"
}
server_sleep_til_boot() {
  while ! server_rpc ping >/dev/null 2>&1; do sleep 0.1; done
}
client_sleep_til_boot() {
  while ! client_rpc ping >/dev/null 2>&1; do sleep 0.1; done
}

mkdir -p $SERVER_DATADIR $CLIENT_DATADIR

echo "-- Starting the demo. You might want to run the two following commands in"
echo "   separate terminal windows:"
echo
echo "   watch -n0.1 tail -n 30 $SERVER_DATADIR/debug.log"
echo "   watch -n0.1 tail -n 30 $CLIENT_DATADIR/debug.log"
echo
read -p "Press [enter] to continue" _

echo
echo "-- IBDing the blocks (height=$BASE_HEIGHT) required to the server node..."
./src/bitcoind -logthreadnames=1 -datadir=$SERVER_DATADIR $CHAIN_HACK_FLAGS -stopatheight=$BASE_HEIGHT >/dev/null

echo
echo "-- Creating snapshot at ~ height $BASE_HEIGHT ($UTXO_DAT_FILE)..."
sleep 2
./src/bitcoind -logthreadnames=1 -datadir=$SERVER_DATADIR $CHAIN_HACK_FLAGS -connect=0 -listen=0 >/dev/null &
SERVER_PID="$!"

server_sleep_til_boot
server_rpc dumptxoutset $UTXO_DAT_FILE
kill -9 $SERVER_PID

# Wait for server to shutdown...
while server_rpc ping >/dev/null 2>&1; do sleep 0.1; done

echo
echo "-- IBDing more blocks to the server node (height=$FINAL_HEIGHT) so there is a diff between snapshot and tip..."
./src/bitcoind -logthreadnames=1 -datadir=$SERVER_DATADIR $CHAIN_HACK_FLAGS -stopatheight=$FINAL_HEIGHT >/dev/null

echo
echo "-- Staring the server node to provide blocks to the client node..."
./src/bitcoind -logthreadnames=1 -datadir=$SERVER_DATADIR $CHAIN_HACK_FLAGS -connect=0 -listen=1 >/dev/null &
SERVER_PID="$!"
server_sleep_til_boot

echo
echo "-- Okay, what you're about to see is the client starting up and activating the snapshot."
echo "   I'm going to display the top 14 log lines from the client on top of an RPC called"
echo "   monitorsnapshot, which is like getblockchaininfo but for both the snapshot and "
echo "   background validation chainstates."
echo
echo "   You're going to first see the snapshot chainstate sync to the server's tip, then"
echo "   the background IBD chain kicks in to validate up to the base of the snapshot."
echo
echo "   Once validation of the snapshot is done, you should see log lines indicating"
echo "   that we've deleted the background validation chainstate."
echo
read -p "When you're ready for all this, hit [enter]" _

echo
echo "-- Starting the client node to get headers from the server, then load the snapshot..."
./src/bitcoind -logthreadnames=1 -datadir=$CLIENT_DATADIR -connect=0 -port=9998 -rpcport=9999 \
  -addnode=127.0.0.1 $CHAIN_HACK_FLAGS >/dev/null &
CLIENT_PID="$!"
client_sleep_til_boot

echo
echo "-- Initial state of the client:"
client_rpc monitorsnapshot

echo
echo "-- Loading UTXO snapshot into client..."
client_rpc loadtxoutset $UTXO_DAT_FILE

watch -n 0.3 "( tail -n 14 $CLIENT_DATADIR/debug.log ; echo ; ./src/bitcoin-cli -rpcport=9999 -datadir=$CLIENT_DATADIR monitorsnapshot) | cat"

echo "-- Okay, now I'm going to restart the client to make sure that the snapshot chain reloads "
echo "   as the main chain properly..."

while kill -0 $CLIENT_PID; do
    sleep 1
done
./src/bitcoind -logthreadnames=1 -datadir=$CLIENT_DATADIR -connect=0 -port=9998 -rpcport=9999 \
  -addnode=127.0.0.1 $CHAIN_HACK_FLAGS >/dev/null &
CLIENT_PID="$!"
client_sleep_til_boot

watch -n 0.3 "( tail -n 14 $CLIENT_DATADIR/debug.log ; echo ; ./src/bitcoin-cli -rpcport=9999 -datadir=$CLIENT_DATADIR monitorsnapshot) | cat"

echo
echo "-- Done!"
