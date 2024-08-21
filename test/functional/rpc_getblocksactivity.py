#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from test_framework.address import address_to_scriptpubkey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.messages import COIN
from test_framework.wallet import MiniWallet, getnewdestination


class GetBlocksActivityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(node, 101)
        _, spk_1, addr_1 = getnewdestination()
        wallet.send_to(from_node=node, scriptPubKey=spk_1, amount=1 * COIN)

        # parent_key = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B"
        to_addr = "mkS4HXoTYWRTescLGaUTGbtTTYX5EjJyEE"
        # send 1.0, mempool only
        # childkey 5 of `parent_key`
        wallet.send_to(
            from_node=node, scriptPubKey=address_to_scriptpubkey(to_addr), amount=1 * COIN)
        blockhash = self.generate(node, 1)[0]

        # Test getblocksactivity
        result = node.getblocksactivity(
            [blockhash], [f"addr({addr_1})", f"addr({to_addr})"], [])
        print(result)
        assert_equal(len(result['activity']), 1)
        assert address in result['activity'][0]


if __name__ == '__main__':
    GetBlocksActivityTest(__file__).main()
