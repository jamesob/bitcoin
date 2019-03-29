// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_H
#define BITCOIN_VALIDATION_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <amount.h>
#include <coins.h>
#include <crypto/common.h> // for ReadLE64
#include <fs.h>
#include <policy/feerate.h>
#include <protocol.h> // For CMessageHeader::MessageStartChars
#include <script/script_error.h>
#include <sync.h>
#include <txmempool.h>
#include <txdb.h>
#include <util/system.h>
#include <versionbits.h>
#include <serialize.h>

#include <algorithm>
#include <atomic>
#include <exception>
#include <map>
#include <memory>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CChainState;
class CBlockIndex;
class CBlockTreeDB;
class CBlockUndo;
class CChainParams;
class CInv;
class CConnman;
class CScriptCheck;
class CBlockPolicyEstimator;
class CTxMemPool;
class CValidationState;
struct ChainTxData;

struct PrecomputedTransactionData;
struct LockPoints;

/** Default for -whitelistrelay. */
static const bool DEFAULT_WHITELISTRELAY = true;
/** Default for -whitelistforcerelay. */
static const bool DEFAULT_WHITELISTFORCERELAY = false;
/** Default for -minrelaytxfee, minimum relay fee for transactions */
static const unsigned int DEFAULT_MIN_RELAY_TX_FEE = 1000;
//! -maxtxfee default
static const CAmount DEFAULT_TRANSACTION_MAXFEE = COIN / 10;
//! Discourage users to set fees higher than this amount (in satoshis) per kB
static const CAmount HIGH_TX_FEE_PER_KB = COIN / 100;
//! -maxtxfee will warn if called with a higher fee than this amount (in satoshis)
static const CAmount HIGH_MAX_TX_FEE = 100 * HIGH_TX_FEE_PER_KB;
/** Default for -limitancestorcount, max number of in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_LIMIT = 25;
/** Default for -limitancestorsize, maximum kilobytes of tx + all in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_SIZE_LIMIT = 101;
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_LIMIT = 25;
/** Default for -limitdescendantsize, maximum kilobytes of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_SIZE_LIMIT = 101;
/** Default for -mempoolexpiry, expiration time for mempool transactions in hours */
static const unsigned int DEFAULT_MEMPOOL_EXPIRY = 336;
/** Maximum kilobytes for transactions to store for processing during reorg */
static const unsigned int MAX_DISCONNECTED_TX_POOL_SIZE = 20000;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB

/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** -par default (number of script-checking threads, 0 = auto) */
static const int DEFAULT_SCRIPTCHECK_THREADS = 0;
/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached its tip. Changing this value is a protocol upgrade. */
static const unsigned int MAX_HEADERS_RESULTS = 2000;
/** Maximum depth of blocks we're willing to serve as compact blocks to peers
 *  when requested. For older blocks, a regular BLOCK response will be sent. */
static const int MAX_CMPCTBLOCK_DEPTH = 5;
/** Maximum depth of blocks we're willing to respond to GETBLOCKTXN requests for. */
static const int MAX_BLOCKTXN_DEPTH = 10;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and pruning harder). We'll probably
 *  want to make this a per-peer adaptive value at some point. */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60;
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 24 * 60 * 60;
/** Maximum length of reject messages. */
static const unsigned int MAX_REJECT_MESSAGE_LENGTH = 111;
/** Block download timeout base, expressed in millionths of the block interval (i.e. 10 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE = 1000000;
/** Additional block download timeout per parallel downloading peer (i.e. 5 min) */
static const int64_t BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 500000;

static const int64_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60;
/** Maximum age of our tip in seconds for us to be considered current for fee estimation */
static const int64_t MAX_FEE_ESTIMATION_TIP_AGE = 3 * 60 * 60;

/** Default for -permitbaremultisig */
static const bool DEFAULT_PERMIT_BAREMULTISIG = true;
static const bool DEFAULT_CHECKPOINTS_ENABLED = true;
static const bool DEFAULT_TXINDEX = false;
static const unsigned int DEFAULT_BANSCORE_THRESHOLD = 100;
/** Default for -persistmempool */
static const bool DEFAULT_PERSIST_MEMPOOL = true;
/** Default for -mempoolreplacement */
static const bool DEFAULT_ENABLE_REPLACEMENT = true;
/** Default for using fee filter */
static const bool DEFAULT_FEEFILTER = true;

/** Maximum number of headers to announce when relaying blocks with headers message.*/
static const unsigned int MAX_BLOCKS_TO_ANNOUNCE = 8;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;

static const bool DEFAULT_PEERBLOOMFILTERS = true;

/** Default for -stopatheight */
static const int DEFAULT_STOPATHEIGHT = 0;

struct BlockHasher
{
    // this used to call `GetCheapHash()` in uint256, which was later moved; the
    // cheap hash function simply calls ReadLE64() however, so the end result is
    // identical
    size_t operator()(const uint256& hash) const { return ReadLE64(hash.begin()); }
};

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern CBlockPolicyEstimator feeEstimator;
extern CTxMemPool mempool;
extern std::atomic_bool g_is_mempool_loaded;
typedef std::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;
extern BlockMap& mapBlockIndex GUARDED_BY(cs_main);
extern const std::string strMessageMagic;
extern Mutex g_best_block_mutex;
extern std::condition_variable g_best_block_cv;
extern uint256 g_best_block;
extern std::atomic_bool fImporting;
extern std::atomic_bool fReindex;
extern int nScriptCheckThreads;
extern bool fIsBareMultisigStd;
extern bool fRequireStandard;
extern bool fCheckBlockIndex;
extern bool fCheckpointsEnabled;
extern size_t nCoinCacheUsage;
/** A fee rate smaller than this is considered zero fee (for relaying, mining and transaction creation) */
extern CFeeRate minRelayTxFee;
/** Absolute maximum transaction fee (in satoshis) used by wallet and mempool (rejects high fee in sendrawtransaction) */
extern CAmount maxTxFee;
/** If the tip is older than this (in seconds), the node is considered to be in initial block download. */
extern int64_t nMaxTipAge;
extern bool fEnableReplacement;

/** Block hash whose ancestors we will assume to have valid scripts without checking them. */
extern uint256 hashAssumeValid;

/** Minimum work we will assume exists on some valid chain. */
extern arith_uint256 nMinimumChainWork;

/** Best header we've seen so far (used for getheaders queries' starting points). */
extern CBlockIndex *pindexBestHeader;

/** Pruning-related variables and constants */
/** True if any block files have ever been pruned. */
extern bool fHavePruned;
/** True if we're running in -prune mode. */
extern bool fPruneMode;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;
/** Block files containing a block-height within MIN_BLOCKS_TO_KEEP of ::ChainActive().Tip() will not be pruned. */
static const unsigned int MIN_BLOCKS_TO_KEEP = 288;
/** Minimum blocks required to signal NODE_NETWORK_LIMITED */
static const unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS = 288;

static const signed int DEFAULT_CHECKBLOCKS = 6;
static const unsigned int DEFAULT_CHECKLEVEL = 3;

// Require that user allocate at least 550 MiB for block & undo files (blk???.dat and rev???.dat)
// At 1MB per block, 288 blocks = 288MB.
// Add 15% for Undo data = 331MB
// Add 20% for Orphan block rate = 397MB
// We want the low water mark after pruning to be at least 397 MB and since we prune in
// full block file chunks, we need the high water mark which triggers the prune to be
// one 128MB block file + added 15% undo data = 147MB greater for a total of 545MB
// Setting the target to >= 550 MiB will make it likely we can respect the target.
static const uint64_t MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 *
 * May not be called in a
 * validationinterface callback.
 *
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and whitelisted peers.
 * @param[out]  fNewBlock A boolean which is set to indicate if the block was first received via this call
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool* fNewBlock) LOCKS_EXCLUDED(cs_main);

/**
 * Process incoming block headers.
 *
 * May not be called in a
 * validationinterface callback.
 *
 * @param[in]  block The block headers themselves
 * @param[out] state This may be set to an Error state if any error occurred processing them
 * @param[in]  chainparams The params for the chain we want to connect to
 * @param[out] ppindex If set, the pointer will be set to point to the last new block index object for the given headers
 * @param[out] first_invalid First header that fails validation, if one exists
 */
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& block, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex = nullptr, CBlockHeader* first_invalid = nullptr) LOCKS_EXCLUDED(cs_main);

/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const FlatFilePos &pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const FlatFilePos &pos);
/** Import blocks from an external file */
bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, FlatFilePos *dbp = nullptr);
/** Ensures we have a genesis block in the block tree, possibly writing one to disk. */
bool LoadGenesisBlock(const CChainParams& chainparams);
/** Load the block tree and coins database from disk,
 * initializing state if we're running with -reindex. */
bool LoadBlockIndex(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
/** Unload database information */
void UnloadBlockIndex();
/** Run an instance of the script checking thread */
void ThreadScriptCheck();
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256& hash, CTransactionRef& tx, const Consensus::Params& params, uint256& hashBlock, const CBlockIndex* const blockIndex = nullptr);
/**
 * Find the best known block, and make it the tip of the block chain
 *
 * May not be called with cs_main held. May not be called in a
 * validationinterface callback.
 */
bool ActivateBestChain(CValidationState& state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

/** Guess verification progress (as a fraction between 0.0=genesis and 1.0=current tip). */
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex* pindex);

/** Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage();

/**
 *  Mark one block file as pruned.
 */
void PruneOneBlockFile(const int fileNumber) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 *  Actually unlink the specified files
 */
void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune);

/** Flush all state, indexes and buffers to disk. */
void FlushStateToDisk(CChainState* chainstate = nullptr);
/** Prune block files and flush state to disk. */
void PruneAndFlush(CChainState* chainstate = nullptr);
/** Prune block files up to a given height */
void PruneBlockFilesManual(int nManualPruneHeight);

/** (try to) add transaction to memory pool
 * plTxnReplaced will be appended to with all transactions replaced from mempool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept=false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state);

/** Get the BIP9 state for a given deployment at the current tip. */
ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the numerical statistics for the BIP9 state for a given deployment at the current tip. */
BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the block height at which the BIP9 deployment switched into the state for the block building on the current tip. */
int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos);


/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight);

/** Transaction validation functions */

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransaction &tx, int flags = -1) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Test whether the LockPoints height and time are still valid on the current chain
 */
bool TestLockPointValidity(const LockPoints* lp) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTxMemPool& pool, const CTransaction& tx, int flags, LockPoints* lp = nullptr, bool useExistingLockPoints = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CTxOut m_tx_out;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool cacheStore;
    ScriptError error;
    PrecomputedTransactionData *txdata;

public:
    CScriptCheck(): ptxTo(nullptr), nIn(0), nFlags(0), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR) {}
    CScriptCheck(const CTxOut& outIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn, PrecomputedTransactionData* txdataIn) :
        m_tx_out(outIn), ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), cacheStore(cacheIn), error(SCRIPT_ERR_UNKNOWN_ERROR), txdata(txdataIn) { }

    bool operator()();

    void swap(CScriptCheck &check) {
        std::swap(ptxTo, check.ptxTo);
        std::swap(m_tx_out, check.m_tx_out);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
        std::swap(txdata, check.txdata);
    }

    ScriptError GetScriptError() const { return error; }
};

/** Initializes the script-execution cache */
void InitScriptExecutionCache();


/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock& block, const FlatFilePos& pos, const Consensus::Params& consensusParams);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams);
bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const FlatFilePos& pos, const CMessageHeader::MessageStartChars& message_start);
bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CBlockIndex* pindex, const CMessageHeader::MessageStartChars& message_start);

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex* pindex);

/** Functions for validating blocks and updating the block tree */

/** Context-independent validity checks */
bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Check a block is completely valid from start to finish (only works on top of our current best block) */
bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Check whether witness commitments are required for block. */
bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params);

/** Check whether NULLDUMMY (BIP 147) has activated. */
bool IsNullDummyEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params);

/** When there are blocks in the active chain with missing data, rewind the chainstate and remove them from the block index */
bool RewindBlockIndex(const CChainParams& params);

/** Update uncommitted block structures (currently: only the witness reserved value). This is safe for submitted blocks. */
void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

/** Produce the necessary coinbase commitment for a block (modifies the hash, don't call for mined blocks). */
std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB {
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(
        CChainState* chainstate,
        const CChainParams& chainparams,
        CCoinsView *coinsview,
        int nCheckLevel,
        int nCheckDepth);
};

inline CBlockIndex* LookupBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

/** Find the last common block between the parameter chain and a locator. */
CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

class ConnectTrace;

/** @see CChainState::FlushStateToDisk */
enum class FlushStateMode {
    NONE,
    IF_NEEDED,
    PERIODIC,
    ALWAYS
};

namespace {
    struct CBlockIndexWorkComparator
    {
        bool operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nChainWork > pb->nChainWork) return false;
            if (pa->nChainWork < pb->nChainWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };
} // anon namespace

/**
 * A convenience class for constructing the CCoinsView* hierarchy used
 * to facilitate access to the UTXO set.
 */
class CoinsViews {

public:
    std::unique_ptr<CCoinsViewDB> m_dbview;
    std::unique_ptr<CCoinsViewErrorCatcher> m_catcherview;
    std::unique_ptr<CCoinsViewCache> m_cacheview;

    CoinsViews(
            std::string ldb_name,
            size_t cache_size_bytes,
            bool in_memory = false,
            bool should_wipe = false)
    {
        m_dbview.reset(new CCoinsViewDB(
            GetDataDir() / ldb_name, cache_size_bytes, in_memory, should_wipe));
        m_catcherview.reset(new CCoinsViewErrorCatcher(m_dbview.get()));
        m_cacheview.reset(new CCoinsViewCache(m_catcherview.get()));
    }
};

// Defined below, but needed for `friend` usage in CChainState.
class ChainstateManager;

/**
 * CChainState stores and provides an API to update our local knowledge of the
 * current best chain.
 *
 * Eventually, the API here is targeted at being exposed externally as a
 * consumable libconsensus library, so any functions added must only call
 * other class member functions, pure functions in other parts of the consensus
 * library, callbacks via the validation interface, or read/write-to-disk
 * functions (eventually this will also be via callbacks).
 *
 * Anything that is contingent on the current tip of the chain is stored here,
 * whereas block information and metadata independent of the current tip is
 * kept in `BlockMetadataManager`.
 */
class CChainState {
private:

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /**
     * the ChainState CriticalSection
     * A lock that must be held when modifying this ChainState - held in ActivateBestChain()
     */
    CCriticalSection m_cs_chainstate;

    /**
     * Is this chainstate undergoing initial block download?
     *
     * Mutable because we need to be able to mark IsInitialBlockDownload()
     * const, which toggles this for caching purposes.
     */
    mutable std::atomic<bool> m_is_ibd;

    //! Manages the UTXO set, which is a reflection of the contents of `m_chain`.
    std::unique_ptr<CoinsViews> m_coins_views;

    /**
     * If true, this chainstate is marked for destruction ASAP and should
     * unload accordingly. We use this indirect marker (instead of calling
     * `Unload()` synchronously) because we might realize we need to unload
     * in the middle of, say, an `ActivateBestChain()` call.
     *
     * @see Unload()
     */
    bool m_should_delete = false;

public:
    CChainState(
        /* parameters forwarded to CoinsViews */
        size_t cache_size_bytes,
        bool in_memory,
        bool should_wipe,
        std::string leveldb_name = "chainstate",
        uint256 from_snapshot_blockhash = uint256()
        ) : m_is_ibd(false),
            m_from_snapshot_blockhash(from_snapshot_blockhash),
            m_coins_cache_size_bytes(cache_size_bytes)
    {
        if (!from_snapshot_blockhash.IsNull()) {
            leveldb_name += "_" + from_snapshot_blockhash.ToString();
        }

        m_coins_views.reset(new CoinsViews(
            leveldb_name, cache_size_bytes, in_memory, should_wipe));
    }

    /**
     * The current chain of blockheaders we consult and build on.
     *
     * @see CChain, CBlockIndex.
     */
    CChain m_chain;

    /**
     * The blockhash which is the base of the snapshot this chainstate was created from.
     *
     * IsNull() if this chainstate was not created from a snapshot.
     */
    uint256 m_from_snapshot_blockhash;

    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

    std::string ToString();

    CCoinsViewCache* CoinsCache() { return m_coins_views->m_cacheview.get(); }
    CCoinsViewDB* CoinsDB() { return m_coins_views->m_dbview.get(); }
    CCoinsViewErrorCatcher* CoinsErrorCatcher() { return m_coins_views->m_catcherview.get(); }
    void ResetCoinsViews() { m_coins_views.reset(); }

    size_t m_coins_cache_size_bytes;

    /**
     * Free members and *delete* the on-disk coinsdb data. Should only be used for
     * background validation chainstates we're throwing away.
     */
    void Delete();

    /**
     * Update the on-disk chain state.
     * The caches and indexes are flushed depending on the mode we're called with
     * if they're too large, if it's been a while since the last write,
     * or always and in all cases if we're in prune mode and are deleting files.
     *
     * If FlushStateMode::NONE is used, then FlushStateToDisk(...) won't do anything
     * besides checking if we need to prune.
     */
    bool FlushStateToDisk(
        const CChainParams& chainparams,
        CValidationState &state,
        FlushStateMode mode,
        int nManualPruneHeight = 0);

     /**
      * Find the best known block, and make it the tip of the block chain
      *
      * May not be called with cs_main held. May not be called in a
      * validationinterface callback.
      */
    bool ActivateBestChain(
        CValidationState& state,
        const CChainParams& chainparams,
        std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());

    bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Block (dis)connection on a given view:
    DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view);
    bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                      CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Block disconnection on our UTXO set:
    bool DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions* disconnectpool) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    // Manual block validity manipulation:

    //! Mark a block as precious and reorganize.
    //! May not be called in a validationinterface callback.
    bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex* pindex) LOCKS_EXCLUDED(cs_main);

    //! Mark a block as invalid.
    bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex);

    //! Remove invalidity status from a block and its descendants.
    void ResetBlockFailureFlags(CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! Replay blocks that aren't fully applied to the database.
    bool ReplayBlocks(const CChainParams& params);

    //! When there are blocks in the active chain with missing data, rewind the
    //! chainstate and remove them from the block index.
    bool RewindBlockIndex(const CChainParams& params);
    bool LoadGenesisBlock(const CChainParams& chainparams);

    void PruneBlockIndexCandidates();

    void UnloadBlockIndex();

    /**
     * Make various assertions about the state of the block index.
     *
     * By default this only executes fully when using the Regtest chain; see: fCheckBlockIndex.
     */
    void CheckBlockIndex(const Consensus::Params& consensusParams);

    /** Check whether we are doing an initial block download (synchronizing from disk or network) */
    bool IsInitialBlockDownload() const;

    /** Update the chain tip based on database information. */
    bool LoadChainTip(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    void ReceivedBlockTransactions(const CBlock& block, CBlockIndex* pindexNew, const FlatFilePos& pos, const Consensus::Params& consensusParams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    CBlockIndex* FindMostWorkChain() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! Mark a block as not having block data
    void EraseBlockData(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    friend ChainstateManager;
};

/** Mark a block as precious and reorganize.
 *
 * May not be called in a
 * validationinterface callback.
 */
bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex) LOCKS_EXCLUDED(cs_main);

/** Mark a block as invalid. */
bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex);

/** Remove invalidity status from a block and its descendants. */
void ResetBlockFailureFlags(CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Serialized version of a UTXO set from which an assumed-valid CChainState
 * can be constructed.
 */
class SnapshotMetadata
{
public:
    CDiskBlockIndex m_base_blockheader;
    uint256 m_utxo_contents_hash = {};
    uint64_t m_coins_count = 0;
    /**
     * Necessary to "fake" the base nChainTx so that we can estimate progress during
     * snapshot IBD.
     */
    unsigned int m_nchaintx = 0;
    bool m_validation_complete = false;

    SnapshotMetadata() { }
    SnapshotMetadata(
        const CDiskBlockIndex& base_blockheader,
        const uint256& utxo_contents_hash,
        uint64_t coins_count,
        unsigned int nchaintx) : m_utxo_contents_hash(utxo_contents_hash),
            m_base_blockheader(base_blockheader), m_coins_count(coins_count),
            m_nchaintx(nchaintx) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(m_base_blockheader);
        READWRITE(m_utxo_contents_hash);
        READWRITE(m_coins_count);
        READWRITE(m_nchaintx);
        READWRITE(m_validation_complete);
    }

};

/**
 * Provides an interface for creating and interacting with multiple
 * chainstates, as well as a means to initialize chainstates from a
 * UTXO snapshot. Managed chainstates can be maintained at different
 * heights simultaneously.
 *
 * This class provides abstractions that allow the retrieval of the current
 * most-work chainstate ("Active") as well as chainstates which may be in
 * background use to validate UTXO snapshots.
 *
 * This class was created to displace the use of global variables (e.g.
 * chainActive) which were historically used to reference a single active
 * chainstate throughout the codebase.
 *
 * TODO jamesob: basically everything in this class is implicitly covered
 *   by `cs_main`. Should probably put some more formalization around
 *   locking and maybe add a class-local `cs` CCriticalSection.
 */
class ChainstateManager
{
private:
    /**
     * Temporary holding place for a snapshot chainstate which is in the process of
     * being constructed. When ready, we swap with `m_snapshot_chainstate`.
     */
    std::unique_ptr<CChainState> m_unready_snapshot_chainstate;

    /**
     * If not empty, this points to metadata corresponding to the UTXO snapshot
     * currently in use.
     */
    std::unique_ptr<SnapshotMetadata> m_snapshot_metadata;

    /**
     * The chainstate used under normal operation (i.e. "regular" IBD) or,
     * if a snapshot is in use, for background validation. Its contents will
     * be freed when background validation of the snapshot has completed.
     */
    std::unique_ptr<CChainState> m_ibd_chainstate GUARDED_BY(cs_main);

    /**
     * A chainstate initialized on the basis of a UTXO snapshot. If this is
     * truthy, it is always our active chainstate unless proven invalid.
     */
    std::unique_ptr<CChainState> m_snapshot_chainstate GUARDED_BY(cs_main);

public:
    /**
     * Points to either the ibd or snapshot chainstate; indicates our
     * most-work chain.
     */
    CChainState* m_active_chainstate GUARDED_BY(cs_main);

    /**
     * Instantiate a new chainstate and assign it based upon whether it is from a snapshot.
     *
     * @param[in] cache_size_bytes   Forwarded to CChainState construction.
     * @param[in] in_memory   Forwarded to CChainState construction.
     * @param[in] should_wipe   Forwarded to CChainState construction.
     * @param[in] activate   If true, make this new chainstate the active one.
     * @param[in] snapshot_blockhash   If given, signify that this chainstate
     *                                 is based on a snapshot.
     * @param[in] snapshot_needs_initialization   If true, we can't use the snapshot chainstate
     *                                            right away as it still needs some setup.
     */
    CChainState* InitializeChainstate(
        size_t cache_size_bytes,
        bool in_memory,
        bool should_wipe,
        bool activate = true,
        const uint256& snapshot_blockhash = uint256(),
        bool snapshot_needs_initialization = false);

    void SaveSnapshotMetadataToDisk() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool DeleteSnapshotMetadataFromDisk() const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    bool LoadSnapshotMetadata() EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Get all chainstates currently being used. */
    std::vector<CChainState*> GetAll();

    /** Run some function on all chainstates in use.  */
    void RunOnAll(const std::function<void(CChainState*)> fn);

    /**
     * Return all chainstates to be checked for next blocks to download.
     *
     * This specifically orders the snapshot chain first (if it exists) to
     * expedite syncing to network tip.
     */
    std::vector<CChainState*> GetAllForBlockDownload();

    /**
     * Construct and activate a Chainstate on the basis of UTXO snapshot data.
     *
     * Steps:
     *
     *   - Initialize an unused CChainState and stash it in
     *     `m_unready_snapshot_chainstate`.
     *
     *   - Load its `CoinsViews` contents from `coins_file`.
     *
     *   - Verify that the hash of the resulting coinsdb matches the expected hash
     *     contained in the snapshot metadata.
     *
     *   - Wait up to 10 minutes for our headers chain to include the "base"
     *     block of the snapshot.
     *
     *   - "Fast forward" the tip of the new chainstate to the base of the snapshot,
     *     faking nTx* block index data along the way.
     *
     *   - Move the new chainstate to `m_snapshot_chainstate` and make it our
     *     ChainstateActive().
     *
     *   - Clear the mempool.
     */
    bool ActivateSnapshot(
        CAutoFile* coins_file, SnapshotMetadata metadata, size_t cache_size_bytes, bool in_memory);

    /**
     * Once the background validation chainstate has reached the height which
     * is the base of the UTXO snapshot in use, compare its coins to ensure
     * they match those expected by the snapshot.
     *
     * If the coins match (expected), then destruct the validation chainstate
     * and continue using the snapshot chainstate as active. Otherwise, revert
     * to using the ibd chainstate and shutdown.
     */
    bool CompleteSnapshotValidation(
        CChainState* validation_chainstate) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Return the relevant chainstate for a new block.
     *
     * Because the use of UTXO snapshots requires the simultaneous maintenance
     * of two chainstates, when a new block message arrives we have to decide
     * which chain we should attempt to append it to.
     *
     * If our most-work chain hasn't seen the incoming blockhash, return that.
     * Otherwise we're likely receiving a block that has already been assumed
     * valid by the snapshot chain, so attempt to append that to the validation
     * chain.
     */
    CChainState* GetChainstateForNewBlock(
        const uint256& blockhash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! The most-work chain.
    CChain& ActiveChain() const;
    int ActiveHeight() const { return ActiveChain().Height(); }
    CBlockIndex* ActiveTip() const { return ActiveChain().Tip(); }
    CCoinsViewCache* ActiveCoinsCache() const { return m_active_chainstate->CoinsCache(); }
    CCoinsViewDB* ActiveCoinsDB() const { return m_active_chainstate->m_coins_views->m_dbview.get(); }

    bool IsSnapshotActive() const
    {
        return m_snapshot_chainstate && m_active_chainstate == m_snapshot_chainstate.get();
    }

    //! Do we have metadata about a snapshot?
    bool HasSnapshotMetadata() const { return !SnapshotBlockhash().IsNull(); }

    uint256 SnapshotBlockhash() const
    {
        return m_snapshot_metadata ? m_snapshot_metadata->m_base_blockheader.GetBlockHash() : uint256{};
    }

    //! Is there a snapshot in use and has it been fully validated?
    bool IsSnapshotValidated() const
    {
        return m_snapshot_metadata ? m_snapshot_metadata->m_validation_complete : false;
    }

    int SnapshotHeight() const {
        return m_snapshot_metadata ? m_snapshot_metadata->m_base_blockheader.nHeight : -1;
    }

    /**
     * @returns true if this chainstate is being used to validate an active
     *          snapshot in the background.
     */
    bool IsBackgroundValidationChainstate(CChainState* chainstate)
    {
        return (m_snapshot_chainstate && chainstate == m_ibd_chainstate.get());
    }

    /**
     * Return the most-work chainstate that has been fully validated.
     *
     * During background validation of a snapshot, this is the ibd chain. After
     * background validation has completed, this is the snapshot chain.
     */
    CChainState* ValidatedChainstate()
    {
        if (m_snapshot_chainstate && IsSnapshotValidated()) {
            return m_snapshot_chainstate.get();
        }
        assert(m_ibd_chainstate);
        return m_ibd_chainstate.get();
    }

    CChain& ValidatedChain() { return ValidatedChainstate()->m_chain; }
    CBlockIndex* ValidatedTip() { return ValidatedChain().Tip(); }

    void Unload()
    {
        RunOnAll([](CChainState* chainstate) {
            chainstate->m_chain.SetTip(nullptr);
            chainstate->UnloadBlockIndex();
        });
    }

    void Reset()
    {
        m_ibd_chainstate.reset();
        m_snapshot_chainstate.reset();
        m_unready_snapshot_chainstate.reset();
        m_active_chainstate = nullptr;
    }

    //! If we're pruning the snapshot chainstate, be sure not to
    //! step on the toes of the background validation by pruning blocks it
    //! might be currently using.
    unsigned int PruneStartHeight(CChainState* chainstate);

    //! Check to see if any of the chainstates under management have signaled
    //! deletion. If so, unlink them.
    void DeleteStaleChainstates();
};

extern ChainstateManager g_chainman;

/** @returns the most-work chainstate. */
CChainState* ChainstateActive();

/** @returns the most-work chain. */
CChain& ChainActive();

/** Global variable that points to the active block tree (protected by cs_main) */
extern std::unique_ptr<CBlockTreeDB> pblocktree;

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache& inputs);

extern VersionBitsCache versionbitscache;

/**
 * Determine what nVersion a new block should use.
 */
int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params);

/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;

/** Get block file info entry for one block file */
CBlockFileInfo* GetBlockFileInfo(size_t n);

/** Dump the mempool to disk. */
bool DumpMempool();

/** Load the mempool from disk. */
bool LoadMempool();

//! Check whether the block associated with this index entry is pruned or not.
inline bool IsBlockPruned(const CBlockIndex* pblockindex)
{
    return (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0);
}

#endif // BITCOIN_VALIDATION_H
