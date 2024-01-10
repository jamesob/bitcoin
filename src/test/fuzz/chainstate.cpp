// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/miner.h>
#include <pow.h>
#include <scheduler.h>
#include <undo.h>
#include <validation.h>
#include <validationinterface.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <util/fs_helpers.h>
#include <util/thread.h>


namespace {

const BasicTestingSetup* g_setup;

class KernelNotifications : public kernel::Notifications
{
public:
    kernel::InterruptResult blockTip(SynchronizationState, CBlockIndex&) override { return {}; }
    void headerTip(SynchronizationState, int64_t height, int64_t timestamp, bool presync) override {}
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override {}
    void warning(const bilingual_str& warning) override {}
    void flushError(const std::string& debug_message) override
    {
        assert(false);
    }
    void fatalError(const std::string& debug_message, const bilingual_str& user_message) override
    {
        assert(false);
    }
};

auto g_notifications{KernelNotifications()};

//! See net_processing.
static const int MAX_HEADERS_RESULTS{2000};

// We use a mapping from file path to buffer as a boutique in-memory file system. Note it's
// fine because we only ever use unique pathnames for block files, but it may cause issues if
// this assumption doesn't hold anymore. ("/a/b/blk0000.dat" and "/a/b/c/../blk0000.dat" point
// to two different buffers.)
// The use of a global does not prevent determinism (since the buffer from one run simply gets
// overwritten in the next) but avoids a 128MB allocation per run. FIXME: is that really true?
std::unordered_map<fs::path, std::vector<unsigned char>, std::hash<std::filesystem::path>> g_files;

//! The initial block chain used to test the chainstate.
std::vector<std::shared_ptr<CBlock>> g_initial_blockchain;

FILE* mock_fopen(const fs::path& file_path, const char* mode)
{
    // Get the file from the map. If it's not there insert it unless it's a file we aren't interested in.
    const auto [data, size]{[&]{
        const auto it = g_files.find(file_path);
        if (it != g_files.end()) return std::make_pair(it->second.data(), it->second.size());
        const auto file_name{PathToString(file_path.filename())};
        // We shouldn't need to store anything else than the blk and rev files.
        if (file_name.find("blk") == std::string::npos && file_name.find("rev") == std::string::npos) {
            std::make_pair(nullptr, 0);
        }
        // NOTE: we do a single large alloc of the max possible file size, as there is no sane way to
        // create shorter files but re-allocate when needed.
        std::vector<unsigned char> buf(node::MAX_BLOCKFILE_SIZE);
        const auto [it2, _]{g_files.insert({file_path, std::move(buf)})};
        return std::make_pair(it2->second.data(), it2->second.size());
    }()};
    if (!data) return (FILE*)nullptr;

    // TODO: implement some fmemopen equivalent on Windows and macOS platforms.
#if defined(MAC_OSX) || defined(WIN_32)
    return (FILE*)nullptr;
#else
    return fmemopen(data, size, mode);
#endif
}

void mock_filesystem_calls()
{
    fs::g_mock_create_dirs = [](const fs::path&) { return true; };
    g_mock_check_disk_space = [](const fs::path&, uint64_t) { return true; };

#if !(defined(MAC_OSX) || defined(WIN_32))
    fsbridge::g_mock_fopen = mock_fopen;
#endif
    fs::g_mock_remove = [&](const fs::path& file_path) {
        g_files.erase(file_path);
        return true;
    };
    fs::g_mock_exists = [&](const fs::path& file_path) {
        return g_files.count(file_path) > 0;
    };
    fs::g_mock_rename = [&](const std::filesystem::path& old_p, const std::filesystem::path& new_p) {
        g_files.extract(old_p).key() = new_p;
    };
    // Needs to be mocked because it may call `fileno(3)`, which returns an error for `fmemopen(3)`ed streams.
    g_mock_file_commit = [&](FILE* f) {
        return fflush(f) == 0;
    };
    // Needs to be mocked because it may call `fileno(3)`, which returns an error for `fmemopen(3)`ed streams.
    g_mock_dir_commit = [&](std::filesystem::path) {};
    // Needs to be mocked because it may call `fileno(3)`, which returns an error for `fmemopen(3)`ed streams.
    g_mock_truncate_file = [&](FILE*, unsigned int) {
        return true;
    };
    // Needs to be mocked because it may call `fileno(3)`, which returns an error for `fmemopen(3)`ed streams.
    g_mock_allocate_file_range = [&](FILE*, unsigned int, unsigned int) {
        return true;
    };
}

/** Consume a random block hash and height to be used as previous block. */
std::pair<uint256, int> RandomPrevBlock(FuzzedDataProvider& prov)
{
    auto hash{ConsumeDeserializable<uint256>(prov).value_or(uint256{})};
    // FIXME: it takes an int but it needs to be positive because there is a conversion to uint inside blockstorage.cpp:
    // node/blockstorage.cpp:968:45: runtime error: implicit conversion from type 'int' of value -2147483648 (32-bit, signed) to type 'unsigned int'
    const auto height{prov.ConsumeIntegralInRange<int>(0, std::numeric_limits<int>::max() - 1)};
    return {std::move(hash), height};
}

/** In 90% of the cases, get any random block from the index. Otherwise generate a random one. */
std::pair<uint256, int> RandomPrevBlock(FuzzedDataProvider& prov, node::BlockManager& blockman) NO_THREAD_SAFETY_ANALYSIS
{
    if (prov.ConsumeIntegralInRange<int>(0, 9) > 0) {
        const auto prev_block{&PickValue(prov, blockman.m_block_index).second};
        return {prev_block->GetBlockHash(), prev_block->nHeight};
    }
    return RandomPrevBlock(prov);
}

/** Create a random block. */
std::pair<CBlockHeader, int> CreateBlockHeader(FuzzedDataProvider& prov, std::pair<uint256, int> prev_block, bool set_merkle = false)
{
    CBlockHeader header;
    header.nVersion = prov.ConsumeIntegral<int32_t>();
    header.nTime = prov.ConsumeIntegral<uint32_t>();
    header.nBits = prov.ConsumeIntegral<uint32_t>();
    header.nNonce = prov.ConsumeIntegral<uint32_t>();
    if (set_merkle) {
        if (auto h = ConsumeDeserializable<uint256>(prov)) {
            header.hashMerkleRoot = *h;
        }
    }
    header.hashPrevBlock = std::move(prev_block.first);
    return std::make_pair(std::move(header), prev_block.second);
}

/** Create a coinbase transaction paying to an anyonecanspend for the given height. */
CTransactionRef CreateCoinbase(int height)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
    tx.vout[0].nValue = 50 * COIN; // We assume we don't mine so many blocks at once..
    tx.vin[0].scriptSig = CScript() << (height + 1) << OP_0;
    return MakeTransactionRef(std::move(tx));
}

/** Create a transaction spending a random amount of utxos from the provided set. Must not be empty. */
CTransactionRef CreateTransaction(FuzzedDataProvider& prov, std::unordered_map<COutPoint, CTxOut, SaltedOutpointHasher>& utxos)
{
    assert(!utxos.empty());
    CMutableTransaction tx;

    const auto input_count{prov.ConsumeIntegralInRange(1, std::min((int)utxos.size(), 1'000))};
    tx.vin.resize(input_count);
    CAmount in_value{0};
    auto it{utxos.begin()};
    for (int i{0}; i < input_count; ++i) {
        auto [outpoint, coin] = *it++;
        in_value += coin.nValue;
        tx.vin[i].prevout = outpoint;
        tx.vin[i].scriptWitness.stack = std::vector<std::vector<uint8_t>>{WITNESS_STACK_ELEM_OP_TRUE};
        utxos.erase(outpoint);
    }

    const auto out_count{prov.ConsumeIntegralInRange(1, 1'000)};
    tx.vout.resize(out_count);
    for (int i{0}; i < out_count; ++i) {
        tx.vout[i].scriptPubKey = P2WSH_OP_TRUE;
        tx.vout[i].nValue = in_value / out_count;
    }

    // Add the coins created in this transaction to the set, for them to be spent by the next
    // ones or in future blocks.
    const auto txid{tx.GetHash()};
    for (int i{0}; i < out_count; ++i) {
        COutPoint outpoint{txid, static_cast<unsigned>(i)};
        CTxOut txo{in_value / out_count, P2WSH_OP_TRUE};
        utxos.emplace(std::move(outpoint), std::move(txo));
    }

    return MakeTransactionRef(std::move(tx));
}

/** Create a random block and include random (and most likely invalid) transactions. */
std::pair<CBlock, int> CreateBlock(FuzzedDataProvider& prov, std::pair<uint256, int> prev_block)
{
    CBlock block;
    auto [block_header, height]{CreateBlockHeader(prov, std::move(prev_block))};
    *(static_cast<CBlockHeader*>(&block)) = std::move(block_header);

    block.vtx.push_back(CreateCoinbase(height));
    while (prov.ConsumeBool()) {
        if (auto tx = ConsumeDeserializable<CMutableTransaction>(prov, TX_WITH_WITNESS)) {
            block.vtx.push_back(MakeTransactionRef(std::move(*tx)));
        }
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);

    return std::make_pair(std::move(block), height);
}

/** Create a consensus-valid random block.
 * If a non-empty list of transactions is passed include them. Otherwise create some random valid transactions
 * from the given utxos. Spent utxos will be erased from the map and created ones will be included. */
CBlock CreateValidBlock(FuzzedDataProvider& prov, const Consensus::Params& params, CBlockIndex* prev_block,
                        std::unordered_map<COutPoint, CTxOut, SaltedOutpointHasher>& utxos, std::vector<CTransactionRef> txs = {})
{
    assert(prev_block);
    CBlock block;
    block.nVersion = prov.ConsumeIntegral<int32_t>();
    block.nNonce = prov.ConsumeIntegral<uint32_t>();
    node::UpdateTime(&block, params, prev_block);
    block.nBits = GetNextWorkRequired(prev_block, &block, params);
    block.hashPrevBlock = prev_block->GetBlockHash();

    // Always create the coinbase. Then if a list of transactions was passed, use that. Otherwise
    // try to create a bunch of new transactions.
    block.vtx.push_back(CreateCoinbase(prev_block->nHeight + 1));
    if (!txs.empty()) {
        block.vtx.reserve(txs.size());
        block.vtx.insert(block.vtx.end(), std::make_move_iterator(txs.begin()), std::make_move_iterator(txs.end()));
        txs.erase(txs.begin(), txs.end());
    } else {
        while (prov.ConsumeBool() && !utxos.empty()) {
            block.vtx.push_back(CreateTransaction(prov, utxos));
            if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
                block.vtx.pop_back();
                break;
            }
        }
    }
    block.hashMerkleRoot = BlockMerkleRoot(block);

    return block;
}

/** Make it possible to sanity check roundtrips to disk. */
bool operator==(const CBlock& a, const CBlock& b)
{
    return a.nVersion == b.nVersion
        && a.nTime == b.nTime
        && a.nBits == b.nBits
        && a.nNonce == b.nNonce
        && a.hashPrevBlock == b.hashPrevBlock
        && a.hashMerkleRoot == b.hashMerkleRoot;
}

/** Add spendable utxos to our cache from the coins database. */
void AppendUtxos(ChainstateManager& chainman, std::unordered_map<COutPoint, CTxOut, SaltedOutpointHasher>& utxos)
{
    LOCK(cs_main);
    chainman.ActiveChainstate().CoinsTip().Sync();

    const auto& coins{chainman.ActiveChainstate().CoinsDB()};
    const auto cur_height{chainman.ActiveHeight()};
    for (auto cursor{coins.Cursor()}; cursor->Valid(); cursor->Next()) {
        COutPoint outpoint;
        Coin coin;
        assert(cursor->GetValue(coin));
        if (coin.IsSpent() || (coin.IsCoinBase() && cur_height - coin.nHeight < COINBASE_MATURITY)) continue;
        assert(cursor->GetKey(outpoint));
        utxos.emplace(std::move(outpoint), std::move(coin.out));
    }
}

} // namespace

void init_blockstorage()
{
    static const auto testing_setup = MakeNoLogFileContext<>(ChainType::MAIN);
    g_setup = testing_setup.get();

    mock_filesystem_calls();

    // Mock the pow check to always pass since it is checked when loading blocks and we don't
    // want to be mining within the target.
    g_check_pow_mock = [](uint256 hash, unsigned int, const Consensus::Params&) {
        return true;
    };
}

FUZZ_TARGET(blockstorage, .init = init_blockstorage)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const auto& chainparams{Params()};

    // Create the BlockManager and its index. The BlockManager file storage is mocked (see
    // the g_mock_* functions above) and the index uses an in-memory LevelDb.
    uint64_t prune_target{0};
    if (fuzzed_data_provider.ConsumeBool()) {
        prune_target = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    }
    node::BlockManager::Options blockman_opts{
        .chainparams = chainparams,
        .prune_target = prune_target,
        .blocks_dir = "blocks",
        .notifications = g_notifications,
    };
    auto blockman{node::BlockManager{*g_setup->m_node.shutdown, std::move(blockman_opts)}};
    {
    LOCK(cs_main);
    blockman.m_block_tree_db = std::make_unique<kernel::BlockTreeDB>(DBParams{
        .path = "", // Memory-only.
        .cache_bytes = nMaxBlockDBCache << 20,
        .memory_only = true,
    });
    }

    // Needed by AddToBlockIndex, reuse it to test both nullptr and not.
    CBlockIndex* dummy_best{nullptr};
    BlockValidationState dummy_valstate;

    // Load the genesis block.
    {
    LOCK(cs_main);
    assert(blockman.m_block_index.count(chainparams.GetConsensus().hashGenesisBlock) == 0);
    const CBlock& block = chainparams.GenesisBlock();
    FlatFilePos blockPos{blockman.SaveBlockToDisk(block, 0, nullptr)};
    assert(!blockPos.IsNull());
    assert(blockman.AddToBlockIndex(block, dummy_best));
    assert(!blockman.m_block_index.empty());
    }

    // This is used to store blocks which were created when accepting their header, to potentially
    // later be stored to disk entirely.
    std::vector<std::pair<CBlock, int>> blocks_in_flight;
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10'000) {
        CallOneOf(fuzzed_data_provider,
            // Add a header to the block index. Sometimes save the header of a full block which could be saved to disk
            // later (see below). Otherwise save a random header for which we'll never store a block.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                LOCK(cs_main);
                auto header{[&]() NO_THREAD_SAFETY_ANALYSIS {
                    LOCK(cs_main);
                    auto prev_block{RandomPrevBlock(fuzzed_data_provider, blockman)};
                    if (fuzzed_data_provider.ConsumeBool()) {
                        auto [block, height]{CreateBlock(fuzzed_data_provider, std::move(prev_block))};
                        auto header{*(static_cast<CBlockHeader*>(&block))};
                        blocks_in_flight.emplace_back(std::move(block), height);
                        return header;
                    } else {
                        return CreateBlockHeader(fuzzed_data_provider, std::move(prev_block), /*set_merkle=*/true).first;
                    }
                }()};
                assert(blockman.AddToBlockIndex(header, dummy_best));
                assert(blockman.LookupBlockIndex(header.GetHash()));
            },
            // Roundtrip the block index database. It should always succeed, since we mock the pow check.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                LOCK(cs_main);
                assert(blockman.WriteBlockIndexDB());
                assert(blockman.LoadBlockIndexDB({}));
                // TODO: somehow compare m_block_tree_db before and after?
            },
            //// Write some random undo data for a random block from the index.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Always at least one block is present but the genesis doesn't have a pprev.
                auto& block = PickValue(fuzzed_data_provider, blockman.m_block_index).second;
                if (block.pprev) {
                    if (auto undo_data = ConsumeDeserializable<CBlockUndo>(fuzzed_data_provider)) {
                        if (WITH_LOCK(::cs_main, return blockman.WriteUndoDataForBlock(*undo_data, dummy_valstate, block))) {
                            CBlockUndo undo_read;
                            assert(blockman.UndoReadFromDisk(undo_read, block));
                            // TODO: assert they're equal?
                        }
                    }
                }
            },
            // Create a new block and roundtrip it to disk. In 50% of the cases, pick a block for which we
            // stored its header already (if there is any), in the rest create a whole new block.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                auto [block, height]{[&] {
                    LOCK(cs_main);
                    if (!blocks_in_flight.empty() && fuzzed_data_provider.ConsumeBool()) {
                        auto ret{std::move(blocks_in_flight.back())};
                        blocks_in_flight.pop_back();
                        return ret;
                    } else {
                        auto prev_block{RandomPrevBlock(fuzzed_data_provider, blockman)};
                        return CreateBlock(fuzzed_data_provider, std::move(prev_block));
                    }
                }()};
                const auto pos{blockman.SaveBlockToDisk(block, height, nullptr)};
                blockman.GetBlockPosFilename(pos);
                CBlock read_block;
                blockman.ReadBlockFromDisk(read_block, pos);
                assert(block == read_block);
            },
            // Kitchen sink.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                LOCK(cs_main);

                CCheckpointData dummy_data;
                blockman.GetLastCheckpoint(dummy_data);

                // Coverage for CheckBlockDataAvailability. It requires the lower and upper blocks to be correctly
                // ordered. There is always at least one block in the index, the genesis.
                const auto sz{blockman.m_block_index.size()};
                auto lower_it{blockman.m_block_index.begin()};
                std::advance(lower_it, fuzzed_data_provider.ConsumeIntegralInRange<decltype(sz)>(0, sz - 1));
                auto upper_it{lower_it};
                while (fuzzed_data_provider.ConsumeBool()) {
                    auto it = std::next(upper_it);
                    if (it == blockman.m_block_index.end()) break;
                    upper_it = it;
                }
                const auto& lower_block{lower_it->second};
                const auto& upper_block{upper_it->second};
                blockman.CheckBlockDataAvailability(upper_block, lower_block);

                // Get coverage for IsBlockPruned.
                blockman.IsBlockPruned(upper_block);
            }
        );
    };

    // At no point do we set an AssumeUtxo snapshot.
    assert(!blockman.m_snapshot_height);
}

void init_chainstate()
{
    static const auto testing_setup = MakeNoLogFileContext<>(ChainType::MAIN);
    g_setup = testing_setup.get();

    mock_filesystem_calls();

    // Make the pow check always pass to be able to mine a chain from inside the target.
    // TODO: we could have two mocks, once which passes, the other which fails. This way we can
    // also fuzz the codepath for invalid pow.
    g_check_pow_mock = [](uint256 hash, unsigned int, const Consensus::Params&) {
        return true;
    };

    // Get 10 spendable UTxOs.
    g_initial_blockchain = CreateBlockChain(110, Params());
}

FUZZ_TARGET(chainstate, .init = init_chainstate)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    const auto& chainparams{Params()};
    const fs::path datadir{""};
    std::unordered_map<COutPoint, CTxOut, SaltedOutpointHasher> utxos;

    CScheduler scheduler;
    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);
    scheduler.m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { scheduler.serviceQueue(); });

    // Create the chainstate..
    uint64_t prune_target{0};
    if (fuzzed_data_provider.ConsumeBool()) {
        prune_target = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
    }
    node::BlockManager::Options blockman_opts{
        .chainparams = chainparams,
        .prune_target = prune_target,
        .blocks_dir = datadir / "blocks",
        .notifications = g_notifications,
    };
    const ChainstateManager::Options chainman_opts{
        .chainparams = chainparams,
        .datadir = "",
        .adjusted_time_callback = NodeClock::now,
        // TODO: make it possible to call CheckBlockIndex() without having set it here, call it in CallOneOf().
        .check_block_index = true,
        .checkpoints_enabled = false,
        .minimum_chain_work = UintToArith256(uint256{}),
        .assumed_valid_block = uint256{},
        .notifications = g_notifications,
    };
    ChainstateManager chainman{*g_setup->m_node.shutdown, chainman_opts, blockman_opts};

    // ..And then load it.
    node::CacheSizes cache_sizes;
    cache_sizes.block_tree_db = 2 << 20;
    cache_sizes.coins_db = 2 << 22;
    cache_sizes.coins = (450 << 20) - (2 << 20) - (2 << 22);
    node::ChainstateLoadOptions load_opts {
        .block_tree_db_in_memory = true,
        .coins_db_in_memory = true,
        .prune = prune_target > 0,
        .require_full_verification = false,
    };
    auto [status, _] = node::LoadChainstate(chainman, cache_sizes, load_opts);
    assert(status == node::ChainstateLoadStatus::SUCCESS);

    // Activate the initial chain.
    BlockValidationState dummy_valstate;
    for (Chainstate* chainstate : chainman.GetAll()) {
        assert(chainstate->ActivateBestChain(dummy_valstate, nullptr));
    }
    for (const auto& block : g_initial_blockchain) {
        bool new_block{false};
        assert(chainman.ProcessNewBlock(block, true, true, &new_block));
        assert(new_block);
    }

    std::vector<CBlock> blocks_in_flight;
    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10'000) {
        // Every so often, update our cache used to create non-coinbase txs.
        if (_count % 100 == 0) AppendUtxos(chainman, utxos);

        CallOneOf(fuzzed_data_provider,
            // Process a list of headers. Most of the time make it process the header of a valid block
            // cached for future processing.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                LOCK(cs_main);
                std::vector<CBlockHeader> headers;

                // In 1% of the cases, generate a random list of headers to be processed. Otherwise, create a single
                // valid block.
                // TODO: make it possible to generate a chain of more than one valid block.
                const bool is_random{fuzzed_data_provider.ConsumeIntegralInRange(0, 99) == 99};
                const int headers_count{is_random ? fuzzed_data_provider.ConsumeIntegralInRange(1, MAX_HEADERS_RESULTS) : 1};
                headers.reserve(headers_count);

                if (is_random) {
                    for (int i = 0; i < headers_count; ++i) {
                        headers.push_back(CreateBlockHeader(fuzzed_data_provider, RandomPrevBlock(fuzzed_data_provider), /*set_merkle=*/true).first);
                    }
                } else {
                    // In 10% of the cases branch off a random header.
                    const bool extend_tip{fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 9) > 0};
                    // The unspent coins to be used to create transactions beside the coinbase in the block to be created.
                    std::unordered_map<COutPoint, CTxOut, SaltedOutpointHasher> empty_utxos;
                    auto& coins{extend_tip ? utxos : empty_utxos};
                    CBlockIndex* prev_block{[&]() NO_THREAD_SAFETY_ANALYSIS {
                        // Sometimes extend the best validated chain, sometimes the best header chain.
                        if (extend_tip) {
                            return fuzzed_data_provider.ConsumeBool() ? chainman.ActiveTip() : chainman.m_best_header;
                        }
                        return &PickValue(fuzzed_data_provider, chainman.m_blockman.m_block_index).second;
                    }()};
                    blocks_in_flight.push_back(CreateValidBlock(fuzzed_data_provider, chainparams.GetConsensus(), prev_block, coins));
                    headers.emplace_back(blocks_in_flight.back());
                }

                const bool min_pow_checked{fuzzed_data_provider.ConsumeBool()};
                const bool res{chainman.ProcessNewBlockHeaders(headers, min_pow_checked, dummy_valstate)};
                assert(res || is_random || !min_pow_checked);
            },
            // Process a block. Most of the time make it proces one of the blocks in flight.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                const bool process_in_flight{!blocks_in_flight.empty() && fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 9) > 0};
                auto block{[&] {
                    if (process_in_flight) {
                        // In 90% of the cases, process a block of which we processed the header already. Note the block
                        // isn't necessarily valid.
                        auto block{std::move(blocks_in_flight.back())};
                        blocks_in_flight.pop_back();
                        return block;
                    } else {
                        // In the rest, sometimes create a new valid block building on top of either our validated chain
                        // tip or the header chain tip.
                        if (fuzzed_data_provider.ConsumeBool()) {
                            const auto prev_block{WITH_LOCK(cs_main, return fuzzed_data_provider.ConsumeBool() ? chainman.ActiveTip() : chainman.m_best_header)};
                            return CreateValidBlock(fuzzed_data_provider, chainparams.GetConsensus(), prev_block, utxos);
                        } else {
                            // For invalid blocks create sometimes an otherwise valid block which branches from any header,
                            // and sometimes a completely random block.
                            if (fuzzed_data_provider.ConsumeBool()) {
                                std::unordered_map<COutPoint, CTxOut, SaltedOutpointHasher> empty_utxos;
                                const auto prev_block{WITH_LOCK(cs_main, return &PickValue(fuzzed_data_provider, chainman.m_blockman.m_block_index).second)};
                                return CreateValidBlock(fuzzed_data_provider, chainparams.GetConsensus(), prev_block, empty_utxos);
                            } else {
                                LOCK(cs_main);
                                return CreateBlock(fuzzed_data_provider, RandomPrevBlock(fuzzed_data_provider)).first;
                            }
                        }
                    }
                }()};
                const bool force_processing{fuzzed_data_provider.ConsumeBool()};
                const bool min_pow_checked{fuzzed_data_provider.ConsumeBool()};
                chainman.ProcessNewBlock(std::make_shared<CBlock>(std::move(block)), force_processing, min_pow_checked, /*new_block=*/nullptr);
            },
            // Create a reorg of any size.
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                const auto cur_height{WITH_LOCK(cs_main, return chainman.ActiveHeight())};
                if (cur_height <= 0) return;

                // Our cache will be invalidated by the reorg.
                utxos.clear();

                // Pick the depth of the reorg, and sometimes record the unconfirmed transactions to re-confirm them.
                const auto reorg_height{fuzzed_data_provider.ConsumeIntegralInRange(1, cur_height)};
                std::vector<CBlock> disconnected_blocks;
                if (fuzzed_data_provider.ConsumeBool()) {
                    disconnected_blocks.resize(cur_height - reorg_height);
                }

                // Get a pointer to the first block in common between the current and the new chain, optionally
                // recording the disconnected transactions as we go.
                auto ancestor{WITH_LOCK(cs_main, return chainman.ActiveTip())};
                while (ancestor->nHeight >= reorg_height) {
                    if (!disconnected_blocks.empty() && (ancestor->nHeight > reorg_height)) {
                        const auto idx{ancestor->nHeight - reorg_height - 1};
                        assert(chainman.m_blockman.ReadBlockFromDisk(disconnected_blocks[idx], *ancestor));
                    }
                    ancestor = ancestor->pprev;
                }

                // Create a chain as long, don't connect it yet.
                {
                LOCK(cs_main);
                for (int i{0}; i < cur_height - reorg_height; ++i) {
                    std::vector<CTransactionRef> txs;
                    if (!disconnected_blocks.empty() && disconnected_blocks[i].vtx.size() > 1) {
                        txs = std::vector<CTransactionRef>{std::make_move_iterator(disconnected_blocks[i].vtx.begin() + 1), std::make_move_iterator(disconnected_blocks[i].vtx.end())};
                        disconnected_blocks[i] = CBlock{};
                    }
                    auto block{CreateValidBlock(fuzzed_data_provider, chainparams.GetConsensus(), ancestor, utxos, std::move(txs))};
                    assert(chainman.AcceptBlock(std::make_shared<CBlock>(std::move(block)), dummy_valstate, &ancestor, true, nullptr, nullptr, true));
                }
                }

                // Make sure the new chain gets connected (a single additional block might not suffice).
                while (chainman.ActiveHeight() <= cur_height) {
                    auto block{CreateValidBlock(fuzzed_data_provider, chainparams.GetConsensus(), ancestor, utxos)};
                    auto res{WITH_LOCK(cs_main, return chainman.AcceptBlock(std::make_shared<CBlock>(std::move(block)), dummy_valstate, &ancestor, true, nullptr, nullptr, true))};
                    assert(res);
                    assert(chainman.ActiveChainstate().ActivateBestChain(dummy_valstate));
                }
            }
        );
    };

    scheduler.stop(); // FIXME: slow.
    GetMainSignals().UnregisterBackgroundSignalScheduler();

    // FIXME: ImportBlocks is insanely slow because we've got 128MiB blk files. Can we find an alternative to be able to
    // exercise the reindex logic?
    // TODO: sometimes run with an assumed chainstate too. One way could be to generate a snapshot during init and
    // sometimes ActivateSnapshot() at the beginning of the harness.
}
