// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Benchmark for CCoinsViewCache retrieval performance.
 *
 * This benchmark tests the performance of retrieving coins from a CCoinsViewCache
 * that sits in front of a LevelDB-backed CCoinsViewDB. It creates a large number
 * of coins, stores them in the database, and then measures the time it takes to
 * perform random retrievals.
 *
 * The benchmark mimics real-world usage by:
 * 1. Setting up a CCoinsViewDB using LevelDB in a temporary directory
 * 2. Creating a CCoinsViewCache with a 10GB maximum size
 * 3. Populating the database with coins
 * 4. Performing random retrievals to measure performance
 */

#include "dbwrapper.h"
#include <bench/bench.h>
#include <coins.h>
#include <txdb.h>
#include <validation.h>
#include <util/fs.h>
#include <util/time.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>

#include <chrono>
#include <iostream>
#include <vector>
#include <random>

static const uint64_t NUM_COINS_TO_CREATE = 6'500'000'000ULL;
static const uint64_t NUM_RETRIEVALS = 6'500'000ULL;
static const uint64_t MAX_CACHE_SIZE_BYTES = 10ULL * 1024 * 1024 * 1024; // 10GB

static void CoinsViewCacheBenchmark(benchmark::Bench& bench)
{
    fs::path tempDir = fs::temp_directory_path() / "bitcoin_bench_coinsview";
    fs::create_directories(tempDir);

    fs::remove_all(tempDir);
    fs::create_directories(tempDir);

    auto dbparams = DBParams{tempDir, 1 << 24};
    auto coins_opts = CoinsViewOptions{};

    CCoinsViewDB* pcoinsdb = new CCoinsViewDB(dbparams, coins_opts);

    // Create a cache in front of the database with 10GB max size
    CCoinsViewCache* pcache = new CCoinsViewCache(pcoinsdb, MAX_CACHE_SIZE_BYTES);
    pcache->SetBestBlock(*uint256::FromHex("deadbeef"));

    FastRandomContext rng(/*fDeterministic=*/true);

    std::vector<std::pair<uint256, uint32_t>> coin_identifiers;
    coin_identifiers.reserve(NUM_RETRIEVALS);

    std::cout << "Creating " << NUM_COINS_TO_CREATE << " coins for benchmark setup..." << std::endl;

    auto start_time = std::chrono::steady_clock::now();

    const int BATCH_SIZE = 100'000;

    for (uint64_t i = 0; i < NUM_COINS_TO_CREATE; i += BATCH_SIZE) {
        for (uint64_t j = 0; j < BATCH_SIZE && (i + j) < NUM_COINS_TO_CREATE; ++j) {
            uint64_t index = i + j;

            // Create a random transaction ID
            uint256 txid;
            for (unsigned int k = 0; k < txid.size() / sizeof(uint64_t); ++k) {
                ((uint64_t*)txid.begin())[k] = rng.rand64();
            }

            // Use deterministic vout to keep it simple
            uint32_t nOut = index % 10; // Limit to 10 outputs per tx for realism

            // Create a new coin
            COutPoint outpoint(Txid::FromUint256(txid), nOut);
            Coin coin;
            coin.out.nValue = index;  // Just use the index as the value
            coin.out.scriptPubKey = CScript() << OP_TRUE;  // Simple script
            coin.nHeight = 1;
            coin.fCoinBase = false;

            // Add coin to the cache
            pcache->AddCoin(outpoint, std::move(coin), false);

            if (coin_identifiers.size() < NUM_RETRIEVALS) {
                if (rng.randrange(256) == 0) {
                    // Keep track of the identifier for later retrieval
                    coin_identifiers.emplace_back(txid, nOut);
                }
            }
        }

        // Flush to database after each batch to avoid excessive memory usage
        pcache->Flush();

        // Progress reporting
        if (i % 1000000 == 0 || i == 0) {
            std::cout << "Created " << i << " coins..." << std::endl;

              auto rn = std::chrono::steady_clock::now();
            // Show time in seconds for more precision
            auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(rn - start_time).count();
            std::cout << "Time elapsed " << elapsed_sec << " seconds ("
                      << elapsed_sec / 60 << "m " << elapsed_sec % 60 << "s)" << std::endl;

            // Skip time estimation when i is 0 (no coins created yet)
            if (i > 0) {
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(rn - start_time).count();
                auto time_per_batch = elapsed_ms / (i / BATCH_SIZE);
                auto batches_left = (NUM_COINS_TO_CREATE - i) / BATCH_SIZE;
                auto est_time_left_ms = time_per_batch * batches_left;

                // Convert milliseconds to a more readable format
                auto est_time_left_sec = est_time_left_ms / 1000;
                auto est_time_left_min = est_time_left_sec / 60;
                auto est_time_left_hours = est_time_left_min / 60;

                std::cout << "Time per coin batch: " << time_per_batch << "ms" << std::endl;
                std::cout << "Time estimated left: "
                          << est_time_left_hours << "h "
                          << (est_time_left_min % 60) << "m "
                          << (est_time_left_sec % 60) << "s" << std::endl;

                // Calculate and display the processing rate
                double coins_per_second = (i * 1000.0) / elapsed_ms;
                std::cout << "Processing rate: " << std::fixed << std::setprecision(1)
                          << coins_per_second << " coins/second" << std::endl;
            }
        }
    }

    // Final flush to ensure all coins are in the database
    pcache->Flush();
    std::cout << "Finished creating coins. Starting benchmark..." << std::endl;

    // Prepare for random access during benchmark
    std::uniform_int_distribution<size_t> rand_idx(0, coin_identifiers.size() - 1);

    // Pre-generate random indices to avoid RNG overhead during benchmarking
    std::vector<size_t> random_indices;
    random_indices.reserve(NUM_RETRIEVALS);
    for (uint64_t i = 0; i < NUM_RETRIEVALS; ++i) {
        random_indices.push_back(rng.rand64() % coin_identifiers.size());
    }

    // Reset the cache to ensure we're measuring cache performance
    pcache->Flush();

    // Benchmark the retrieval performance
    bench.run([&]() {
        for (uint64_t i = 0; i < NUM_RETRIEVALS; ++i) {
            // Get a pre-generated random coin identifier
            size_t idx = random_indices[i];
            const auto& [txid, nOut] = coin_identifiers[idx];

            // Retrieve the coin from the cache
            COutPoint outpoint(Txid::FromUint256(txid), nOut);
            auto found = pcache->GetCoin(outpoint);
        }
    });

    delete pcache;
    delete pcoinsdb;

    try {
        fs::remove_all(tempDir);
    } catch (const std::exception& e) {
        std::cerr << "Error cleaning up temporary directory: " << e.what() << std::endl;
    }
}

BENCHMARK(CoinsViewCacheBenchmark, benchmark::PriorityLevel::HIGH);
