// Copyright (c) 2013-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/interpreter.h>
#include <script/signingprovider.h>
#include <serialize.h>
#include <addresstype.h>
#include <validation.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <common/system.h>
#include <random.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

namespace {
    typedef std::vector<unsigned char> valtype;
    typedef Span<const unsigned char> Raw;

    static const unsigned char test1_expected_result[32] = {
        0x7c, 0xf7, 0x81, 0x30, 0xd1, 0x3d, 0x08, 0xb2,
        0xc6, 0xc6, 0xb2, 0xd9, 0x2e, 0xf1, 0xf2, 0xdd,
        0x72, 0x1a, 0xd7, 0x09, 0xaa, 0x81, 0x37, 0x12,
        0x53, 0xa6, 0xf1, 0xb6, 0x44, 0x96, 0x6f, 0x26
    };

    static const unsigned char test2_expected_result[32] = {
        0x0f, 0xbe, 0x7f, 0xb7, 0xc3, 0xad, 0x59, 0x2c,
        0x5e, 0x87, 0x95, 0x17, 0x75, 0x7f, 0xfc, 0x6a,
        0x1e, 0xab, 0x8a, 0x94, 0xeb, 0x87, 0x94, 0xcd,
        0x82, 0xeb, 0x0d, 0xfc, 0x74, 0xe4, 0xbf, 0xec 
    };
}

BOOST_FIXTURE_TEST_SUITE(pchash_tests, BasicTestingSetup)

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_from_data)
{
    uint256 hash1 = PairCommitHash(
        // "Hello "
        valtype{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20},
        // "World!"
        valtype{0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21}
    );
    BOOST_CHECK_EQUAL(hash1, uint256(test1_expected_result));

    uint256 hash2 = PairCommitHash(
        // "Hello"
        valtype{0x48, 0x65, 0x6c, 0x6c, 0x6f},
        // " World!"
        valtype{0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21}
    );
    BOOST_CHECK_EQUAL(hash2, uint256(test2_expected_result));
}

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_reproduce)
{
    // pc_tag_hash = SHA256("PairCommit")
    uint256 pc_tag_hash;
    std::string pc_tag = "PairCommit";
    CSHA256().Write((const unsigned char*)pc_tag.data(), pc_tag.size()).Finalize(pc_tag_hash.begin());

    // "Hello "
    const valtype x1 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20};
    // "World!"
    const valtype x2 = {0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    // CompactSize(6)
    const valtype x1_size = {0x06};
    // CompactSize(6)
    const valtype x2_size = {0x06};

    uint256 hash1 = PairCommitHash(x1, x2);

    HashWriter ss;
    ss << Raw{pc_tag_hash}
       << Raw{pc_tag_hash}
       << Raw{x1_size}
       << Raw{x1}
       << Raw{x2_size}
       << Raw{x2};

    uint256 hash2 = ss.GetSHA256();

    BOOST_CHECK_EQUAL(hash1, hash2);
}

// Goal: check that PC Hash Function generate correct hash
BOOST_AUTO_TEST_CASE(pchash_reproduce_edge)
{
    // pc_tag_hash = SHA256("PairCommit")
    uint256 pc_tag_hash;
    std::string pc_tag = "PairCommit";
    CSHA256().Write((const unsigned char*)pc_tag.data(), pc_tag.size()).Finalize(pc_tag_hash.begin());

    FastRandomContext rng;
    // empty
    const valtype x1 = {};
    // 520 random bytes
    const valtype x2{rng.randbytes(520)};
    // CompactSize(0)
    const valtype x1_size = {0x00};
    // CompactSize(520)
    const valtype x2_size = {0xfd, 0x08, 0x02};

    uint256 hash1 = PairCommitHash(x1, x2);

    HashWriter ss;
    ss << Raw{pc_tag_hash}
       << Raw{pc_tag_hash}
       << Raw{x1_size}
       << Raw{x1}
       << Raw{x2_size}
       << Raw{x2};

    uint256 hash2 = ss.GetSHA256();

    BOOST_CHECK_EQUAL(hash1, hash2);
}


namespace {

    bool TapscriptCheck(const valtype& witVerifyScript, const std::vector<valtype>& witData)
    {
        // Build a taproot address...
        XOnlyPubKey key_inner{ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")};
        TaprootBuilder builder;
        builder.Add(/*depth=*/0, witVerifyScript, TAPROOT_LEAF_TAPSCRIPT, /*track=*/true);
        builder.Finalize(key_inner);

        CScriptWitness witness;
        witness.stack.insert(witness.stack.begin(), witData.begin(), witData.end());
        witness.stack.push_back(witVerifyScript);
        auto controlblock = *(builder.GetSpendData().scripts[{witVerifyScript, TAPROOT_LEAF_TAPSCRIPT}].begin());
        witness.stack.push_back(controlblock);

        uint32_t flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_PAIRCOMMIT;
        CScript scriptPubKey = CScript() << OP_1 << ToByteVector(builder.GetOutput());

        CMutableTransaction txFrom;
        txFrom.vout.resize(1);
        txFrom.vout[0].scriptPubKey = scriptPubKey;
        txFrom.vout[0].nValue = 10000;

        CMutableTransaction txTo;
        txTo.vin.resize(1);
        txTo.vin[0].prevout.n = 0;
        txTo.vin[0].prevout.hash = txFrom.GetHash();
        txTo.vin[0].scriptWitness = witness;

        PrecomputedTransactionData txdata(txTo);

        return CScriptCheck(txFrom.vout[0], CTransaction(txTo), 0, flags, false, &txdata)();
    }
}

// Goal: check that OP_PAIRCOMMIT behaves as expected in script
BOOST_AUTO_TEST_CASE(pchash_tapscript)
{
    CScript script;

    // "Hello "
    const valtype x1 = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20};
    // "World!"
    const valtype x2 = {0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};

    // <expected_result> | <x1> <x2> OP_PAIRCOMMIT OP_EQUAL
    script
        << ToByteVector(x1)
        << ToByteVector(x2)
        << OP_PAIRCOMMIT
        << OP_EQUAL;

    const valtype witVerifyScript = ToByteVector(script);

    // Positive test: script must VERIFY with <test1_expected_result>
    const std::vector<valtype> witData1{ ToByteVector(uint256{test1_expected_result}) };

    bool verify = TapscriptCheck(witVerifyScript, witData1);

    BOOST_CHECK(verify);

    // Negative test: script must FAIL with <test2_expected_result>
    const std::vector<valtype> witData2{ ToByteVector(uint256{test2_expected_result}) };

    bool fail = !TapscriptCheck(witVerifyScript, witData2);

    BOOST_CHECK(fail);
}

BOOST_AUTO_TEST_SUITE_END()
