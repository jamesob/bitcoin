// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_CHAINSTATE_H
#define BITCOIN_INIT_CHAINSTATE_H

#include <cstdint> // for int64_t
#include <functional> // for std::function
#include <optional> // for std::optional

class CChainParams;
class ChainstateManager;
class CTxMemPool;

enum class ChainstateLoadingError {
    ERROR_LOADING_BLOCK_DB,
    ERROR_BAD_GENESIS_BLOCK,
    ERROR_PRUNED_NEEDS_REINDEX,
    ERROR_LOAD_GENESIS_BLOCK_FAILED,
    ERROR_CHAINSTATE_UPGRADE_FAILED,
    ERROR_REPLAYBLOCKS_FAILED,
    ERROR_LOADCHAINTIP_FAILED,
    ERROR_GENERIC_BLOCKDB_OPEN_FAILED,
    ERROR_BLOCKS_WITNESS_INSUFFICIENTLY_VALIDATED,
    ERROR_BLOCK_FROM_FUTURE,
    ERROR_CORRUPTED_BLOCK_DB,
};

std::optional<ChainstateLoadingError> LoadChainstateSequence(bool fReset,
                                                             ChainstateManager& chainman,
                                                             CTxMemPool* mempool,
                                                             bool fPruneMode,
                                                             const CChainParams& chainparams,
                                                             bool fReindexChainState,
                                                             int64_t nBlockTreeDBCache,
                                                             int64_t nCoinDBCache,
                                                             int64_t nCoinCacheUsage,
                                                             unsigned int check_blocks,
                                                             unsigned int check_level,
                                                             std::function<int64_t()> get_unix_time_seconds,
                                                             std::optional<std::function<void()>> coins_error_cb = std::nullopt,
                                                             std::optional<std::function<void()>> verifying_blocks_cb = std::nullopt);
#endif // BITCOIN_INIT_CHAINSTATE_H
