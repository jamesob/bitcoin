// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSTATS_H
#define BITCOIN_COINSTATS_H

#include <coins.h>
#include <chain.h>
#include <uint256.h>
#include <sync.h>

extern CCriticalSection cs_main;
CBlockIndex* LookupBlockIndex(const uint256& blockhash);

struct CCoinsStats
{
    int nHeight;
    uint256 hashBlock;
    uint64_t nTransactions;
    uint64_t nTransactionOutputs;
    uint64_t nBogoSize;
    uint256 hashSerialized;
    uint64_t nDiskSize;
    CAmount nTotalAmount;

    // The number of coins contained.
    uint64_t coins_count;

    CCoinsStats() : nHeight(0), nTransactions(0), nTransactionOutputs(0), nBogoSize(0), nDiskSize(0), nTotalAmount(0), coins_count(0) {}
};

//! Calculate statistics about the unspent transaction output set
bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats);

#endif // BITCOIN_COINSTATS_H
