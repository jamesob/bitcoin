// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init/chainstate.h>

#include <chainparams.h> // for CChainParams
#include <node/blockstorage.h> // for CleanupBlockRevFiles, fHavePruned, fReindex
#include <shutdown.h> // for ShutdownRequested
#include <timedata.h> // for GetAdjustedTime
#include <validation.h> // for a lot of things

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
                                                             std::optional<std::function<void()>> coins_error_cb,
                                                             std::optional<std::function<void()>> verifying_blocks_cb) {
    auto is_coinsview_empty = [&](CChainState* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return fReset || fReindexChainState || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    {
        LOCK(cs_main);
        chainman.InitializeChainstate(mempool);
        chainman.m_total_coinstip_cache = nCoinCacheUsage;
        chainman.m_total_coinsdb_cache = nCoinDBCache;

        UnloadBlockIndex(mempool, chainman);

        auto& pblocktree{chainman.m_blockman.m_block_tree_db};
        // new CBlockTreeDB tries to delete the existing file, which
        // fails if it's still open from the previous loop. Close it first:
        pblocktree.reset();
        pblocktree.reset(new CBlockTreeDB(nBlockTreeDBCache, false, fReset));

        if (fReset) {
            pblocktree->WriteReindexing(true);
            //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
            if (fPruneMode)
                CleanupBlockRevFiles();
        }

        if (ShutdownRequested()) return std::nullopt;

        // LoadBlockIndex will load fHavePruned if we've ever removed a
        // block file from disk.
        // Note that it also sets fReindex based on the disk flag!
        // From here on out fReindex and fReset mean something different!
        if (!chainman.LoadBlockIndex()) {
            if (ShutdownRequested()) return std::nullopt;
            return ChainstateLoadingError::ERROR_LOADING_BLOCK_DB;
        }

        // If the loaded chain has a wrong genesis, bail out immediately
        // (we're likely using a testnet datadir, or the other way around).
        if (!chainman.BlockIndex().empty() &&
                !chainman.m_blockman.LookupBlockIndex(chainparams.GetConsensus().hashGenesisBlock)) {
            return ChainstateLoadingError::ERROR_BAD_GENESIS_BLOCK;
        }

        // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
        // in the past, but is now trying to run unpruned.
        if (fHavePruned && !fPruneMode) {
            return ChainstateLoadingError::ERROR_PRUNED_NEEDS_REINDEX;
        }

        // At this point blocktree args are consistent with what's on disk.
        // If we're not mid-reindex (based on disk + args), add a genesis block on disk
        // (otherwise we use the one already on disk).
        // This is called again in ThreadImport after the reindex completes.
        if (!fReindex && !chainman.ActiveChainstate().LoadGenesisBlock()) {
            return ChainstateLoadingError::ERROR_LOAD_GENESIS_BLOCK_FAILED;
        }

        // At this point we're either in reindex or we've loaded a useful
        // block tree into BlockIndex()!

        for (CChainState* chainstate : chainman.GetAll()) {
            chainstate->InitCoinsDB(
                /* cache_size_bytes */ nCoinDBCache,
                /* in_memory */ false,
                /* should_wipe */ fReset || fReindexChainState);

            if (coins_error_cb.has_value()) {
                chainstate->CoinsErrorCatcher().AddReadErrCallback(coins_error_cb.value());
            }

            // If necessary, upgrade from older database format.
            // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
            if (!chainstate->CoinsDB().Upgrade()) {
                return ChainstateLoadingError::ERROR_CHAINSTATE_UPGRADE_FAILED;
            }

            // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
            if (!chainstate->ReplayBlocks()) {
                return ChainstateLoadingError::ERROR_REPLAYBLOCKS_FAILED;
            }

            // The on-disk coinsdb is now in a good state, create the cache
            chainstate->InitCoinsCache(nCoinCacheUsage);
            assert(chainstate->CanFlushToDisk());

            if (!is_coinsview_empty(chainstate)) {
                // LoadChainTip initializes the chain based on CoinsTip()'s best block
                if (!chainstate->LoadChainTip()) {
                    return ChainstateLoadingError::ERROR_LOADCHAINTIP_FAILED;
                }
                assert(chainstate->m_chain.Tip() != nullptr);
            }
        }
    }

    if (!fReset) {
        LOCK(cs_main);
        auto chainstates{chainman.GetAll()};
        if (std::any_of(chainstates.begin(), chainstates.end(),
                        [](const CChainState* cs) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return cs->NeedsRedownload(); })) {
            return ChainstateLoadingError::ERROR_BLOCKS_WITNESS_INSUFFICIENTLY_VALIDATED;
        }
    }

    {
        LOCK(cs_main);

        for (CChainState* chainstate : chainman.GetAll()) {
            if (!is_coinsview_empty(chainstate)) {
                if (verifying_blocks_cb.has_value()) {
                    verifying_blocks_cb.value()();
                }

                const CBlockIndex* tip = chainstate->m_chain.Tip();
                if (tip && tip->nTime > GetAdjustedTime() + 2 * 60 * 60) {
                    return ChainstateLoadingError::ERROR_BLOCK_FROM_FUTURE;
                }

                if (!CVerifyDB().VerifyDB(
                        *chainstate, chainparams, chainstate->CoinsDB(),
                        check_level,
                        check_blocks)) {
                    return ChainstateLoadingError::ERROR_CORRUPTED_BLOCK_DB;
                }
            }
        }
    }

    return std::nullopt;
}
