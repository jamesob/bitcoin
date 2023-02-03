#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test vaults implemented with OP_VAULT.

See the `VaultSpec` class and nearby functions for a general sense of the
transactional structure of vaults.
"""

import copy
import typing as t
from collections import defaultdict, Counter

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import CScript, OP_VAULT, OP_VAULT_RECOVER
from test_framework.messages import CTransaction, COutPoint, CTxOut, CTxIn, COIN
from test_framework.util import assert_equal, assert_raises_rpc_error

from test_framework import script, key, messages


class RecoveryAuthorization:
    """
    Handles generating sPKs and corresponding spend scripts for the optional
    recovery authorization.
    """
    script: CScript = CScript()

    def get_spend_wit_stack(self, *args, **kwargs) -> t.List[bytes]:
        return []


class VaultsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [
            [
                # Use only one script thread to get the exact reject reason for testing
                "-par=1",
                # 0-value outputs, probably among other things in OP_VAULT, are
                # non-standard until transaction v3 policy gets merged.
                "-acceptnonstdtxn=1",
                # TODO: remove when package relay submission becomes a thing.
                "-minrelaytxfee=0",
                # "-dustrelayfee=0",
            ]
        ]
        self.setup_clean_chain = True

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        # Generate some matured UTXOs to spend into vaults.
        self.generate(wallet, 200)

        for recovery_auth in (NoRecoveryAuth(),
                              ChecksigRecoveryAuth()):
            def title(msg: str) -> None:
                self.log.info("[%s] %s", recovery_auth.__class__.__name__, msg)

            title("testing normal vault spend")
            self.single_vault_test(node, wallet, recovery_auth)

            title("testing recovery from the vault")
            self.single_vault_test(
                node, wallet, recovery_auth, recover_from_vault=True)

            title("testing recovery from the unvault trigger")
            self.single_vault_test(
                node, wallet, recovery_auth, recover_from_unvault=True)

            title("testing a batch recovery operation across multiple vaults")
            self.test_batch_recovery(node, wallet, recovery_auth)

            title("testing a batch unvault")
            self.test_batch_unvault(node, wallet, recovery_auth)

            title("testing revaults")
            self.test_revault(node, wallet, recovery_auth)

            title("testing that recoveries must be replaceable")
            self.test_nonreplaceable_recovery(node, wallet, recovery_auth)

            if recovery_auth.__class__ != NoRecoveryAuth:
                title("testing that recovery authorization is checked")
                self.test_authed_recovery_witness_check(node, wallet, recovery_auth)

        # self.log.info("testing recursive recovery attack")
        # self.test_recursive_recovery_witness(node, wallet)

        self.log.info("testing unauth'd recovery")
        self.test_unauthed_recovery(node, wallet)

        self.log.info("testing bad spend delay")
        self.test_bad_spend_delay(node, wallet)

        self.log.info("testing bad vout idx")
        self.test_bad_vout_idx(node, wallet)

    def single_vault_test(
        self,
        node,
        wallet,
        recovery_auth: RecoveryAuthorization,
        recover_from_vault: bool = False,
        recover_from_unvault: bool = False,
    ):
        """
        Test the creation and spend of a single vault, optionally recovering at various
        stages of the vault lifecycle.
        """
        assert_equal(node.getmempoolinfo()["size"], 0)

        vault = VaultSpec(recovery_auth=recovery_auth)
        vault_init_tx = vault.get_initialize_vault_tx(wallet)

        self.assert_broadcast_tx(vault_init_tx, mine_all=True)

        if recover_from_vault:
            assert vault.vault_outpoint
            recov_map = {vault: vault.vault_outpoint}
            self.test_all_bad_recovery_types(recovery_auth, recov_map)
            recovery_tx = get_recovery_tx(recov_map)
            self.assert_broadcast_tx(recovery_tx, mine_all=True)
            return

        assert vault.total_amount_sats and vault.total_amount_sats > 0
        target_amounts = split_vault_value(vault.total_amount_sats)
        target_keys = [
            key.ECKey(secret=(4 + i).to_bytes(32, "big"))
            for i in range(len(target_amounts))
        ]

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=amt, scriptPubKey=make_segwit0_spk(key))
            for amt, key in zip(target_amounts, target_keys)
        ]

        badbehavior = [
            BadTriggerRecoveryPath,
            BadTriggerSpendDelay,
            BadTriggerAmountLow,
            BadTriggerAmountHigh,
            BadTriggerWithdrawOpcode,
            BadTriggerRecoverOpcode,
        ]
        for bb in badbehavior:
            self.log.info("  bad tx: %s", bb.desc)
            unvault_spec = UnvaultSpec([vault], final_target_vout, bad_behavior={bb})
            start_unvault_tx = get_trigger_tx([unvault_spec])
            self.assert_broadcast_tx(start_unvault_tx, err_msg=bb.err)

        unvault_spec = UnvaultSpec([vault], final_target_vout)
        start_unvault_tx = get_trigger_tx([unvault_spec])

        start_unvault_txid = self.assert_broadcast_tx(start_unvault_tx)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(start_unvault_txid), byteorder="big"), n=0
        )

        if recover_from_unvault:
            recov_map = {vault: unvault_outpoint}
            self.test_all_bad_recovery_types(recovery_auth, recov_map, start_unvault_tx)
            recovery_tx = get_recovery_tx(recov_map, start_unvault_tx)
            self.assert_broadcast_tx(recovery_tx, mine_all=True)
            return

        final_tx = get_final_withdrawal_tx(unvault_outpoint, unvault_spec)

        # Broadcasting before start_unvault is confirmed fails.
        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        XXX_mempool_fee_hack_for_no_pkg_relay(node, start_unvault_txid)

        # Generate almost past the timelock, but not quite.
        self.generate(wallet, vault.spend_delay - 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        self.generate(wallet, 1)

        # Generate bad nSequence values.
        final_bad = copy.deepcopy(final_tx)
        final_bad.vin[0].nSequence = final_tx.vin[0].nSequence - 1
        self.assert_broadcast_tx(final_bad, err_msg="Locktime requirement not")

        # Generate bad amounts.
        final_bad = copy.deepcopy(final_tx)
        final_bad.vout[0].nValue = final_tx.vout[0].nValue - 1
        self.assert_broadcast_tx(final_bad, err_msg="failed an OP_CHECKTEMPLATEVERIFY")

        # Finally the unvault completes.
        self.assert_broadcast_tx(final_tx, mine_all=True)

    def test_batch_recovery(
        self,
        node,
        wallet,
        recovery_auth: RecoveryAuthorization,
    ):
        """
        Test generating multiple vaults and recovering them to the recovery path in batch.

        One of the vaults has been triggered for withdrawal while the other two
        are still vaulted.
        """
        # Create some vaults with the same unvaulting key, recovery key, but different
        # spend delays.
        vaults = [
            VaultSpec(spend_delay=i, recovery_auth=recovery_auth) for i in [10, 11, 12]
        ]

        # Ensure that vaults with different recovery keys can be swept in the same
        # transaction, using the same fee management.
        vault_diff_recovery = VaultSpec(
            recovery_secret=(DEFAULT_RECOVERY_SECRET + 10),
            recovery_auth=recovery_auth,
        )

        for v in vaults + [vault_diff_recovery]:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults + [vault_diff_recovery]))
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Start unvaulting the first vault.
        first_unvault_spec = UnvaultSpec([vaults[0]], [])
        unvault1_tx = get_trigger_tx([first_unvault_spec])
        unvault1_txid = unvault1_tx.rehash()
        assert_equal(
            node.sendrawtransaction(unvault1_tx.serialize().hex()), unvault1_txid,
        )

        XXX_mempool_fee_hack_for_no_pkg_relay(node, unvault1_txid)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # So now, 1 vault is in the process of unvaulting and the other two are still
        # vaulted. Recover them all with one transaction.
        unvault1_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(unvault1_txid), byteorder="big"), n=0
        )

        assert vaults[1].vault_outpoint
        assert vaults[2].vault_outpoint
        assert vault_diff_recovery.vault_outpoint

        outpoint_map = {
            vaults[0]: unvault1_outpoint,
            vaults[1]: vaults[1].vault_outpoint,
            vaults[2]: vaults[2].vault_outpoint,
            vault_diff_recovery: vault_diff_recovery.vault_outpoint,
        }

        # The no-recovery-auth case is different from an authorized recovery.
        if recovery_auth.__class__ == NoRecoveryAuth:
            bad_tx = get_recovery_tx(outpoint_map, unvault1_tx)

            # Will fail due to extra recovery-incompatible vault input.
            self.assert_broadcast_tx(bad_tx, err_msg='recovery transaction has bad output structure')

            outpoint_map.pop(vault_diff_recovery)

            bad_tx = get_recovery_tx(outpoint_map, unvault1_tx, fee_wallet=wallet)

            # Will fail due to extra non-vault fee input.
            self.assert_broadcast_tx(bad_tx, err_msg='recovery transaction has bad output structure')

            self.test_all_bad_recovery_types(recovery_auth, outpoint_map, unvault1_tx)

            # Finally okay.
            recovery_tx = get_recovery_tx(outpoint_map, unvault1_tx)
            assert_equal(len(recovery_tx.vout), 2)
            self.assert_broadcast_tx(recovery_tx, mine_all=True)
        else:
            # Test authorized recoveries, which are much more flexible.
            idx_error = {
                1: "vault-insufficient-recovery-value",
                2: "recovery output nValue too low",
            }

            # TODO clean this up; first vout is the fee bump. too implicit right now.
            for i, mutator in enumerate([vout_amount_mutator(vout_idx, -1) for vout_idx in [1, 2]]):
                self.log.info(f"  bad recovery tx: {idx_error[i + 1]}")
                bad_tx = get_recovery_tx(
                    outpoint_map, unvault1_tx,
                    fee_wallet=wallet,
                    presig_tx_mutator=mutator,
                )
                self.assert_broadcast_tx(bad_tx, err_msg=idx_error[i + 1])

            self.test_all_bad_recovery_types(
                recovery_auth, outpoint_map, unvault1_tx, fee_wallet=wallet)

            recovery_tx = get_recovery_tx(
                outpoint_map, unvault1_tx, fee_wallet=wallet)

            idxs = list(range(len(recovery_tx.vout)))
            assert_equal(len(idxs), 4)
            self.assert_broadcast_tx(recovery_tx, mine_all=True)

    def test_batch_unvault(
        self,
        node,
        wallet,
        recovery_auth: RecoveryAuthorization,
    ):
        """
        Test generating multiple vaults and ensure those with compatible parameters
        (spend delay and recovery path) can be unvaulted in batch.
        """
        common_spend_delay = 10
        # Create some vaults with the same spend delay and recovery key, so that they
        # can be unvaulted together, but different unvault keys.
        vaults = [
            VaultSpec(spend_delay=common_spend_delay,
                      unvault_trigger_secret=i) for i in [10, 11, 12]
        ]
        # Create a vault with a different recovery path than the vaults above; cannot
        # be batch unvaulted.
        vault_diff_recovery = VaultSpec(
            spend_delay=10, recovery_secret=(DEFAULT_RECOVERY_SECRET + 1))

        # Create a vault with the same recovery path but a different spend delay;
        # cannot be batch unvaulted.
        vault_diff_delay = VaultSpec(spend_delay=(common_spend_delay - 1))

        for v in vaults + [vault_diff_recovery, vault_diff_delay]:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults) + 2)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Construct the final unvault target.
        unvault_total_sats = sum(v.total_amount_sats for v in vaults)  # type: ignore
        assert unvault_total_sats > 0
        target_key = key.ECKey(secret=(1).to_bytes(32, "big"))

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=unvault_total_sats,
                   scriptPubKey=make_segwit0_spk(target_key))
        ]

        # Ensure that we can't batch with incompatible OP_VAULTs.
        for incompat_vaults in [[vault_diff_recovery],
                                [vault_diff_delay],
                                [vault_diff_recovery, vault_diff_delay]]:
            spec = UnvaultSpec(vaults + incompat_vaults, final_target_vout)
            failed_unvault = get_trigger_tx([spec])
            self.assert_broadcast_tx(
                failed_unvault, err_msg="Trigger outputs not compatible")

        unvault_spec = UnvaultSpec(vaults, final_target_vout)
        good_batch_unvault = get_trigger_tx([unvault_spec])
        good_txid = self.assert_broadcast_tx(good_batch_unvault, mine_all=True)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(good_txid), byteorder="big"), n=0
        )
        final_tx = get_final_withdrawal_tx(unvault_outpoint, unvault_spec)

        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        self.generate(node, common_spend_delay)

        # Finalize the batch withdrawal.
        self.assert_broadcast_tx(final_tx, mine_all=True)

    def test_revault(
        self,
        node,
        wallet,
        recovery_auth: RecoveryAuthorization,
    ):
        """
        Test that some amount can be "revaulted" during the unvault process. That
        amount is immediately deposited back into the same vault that is currently
        undergoing unvaulting, so that the remaining balance within the vault can
        be managed independent of the timelock that the first unvault process has
        induced.
        """
        common_spend_delay = 10
        # To support revaults when dealing with a batch, each vault must share the
        # same vault sPK.
        vaults = [
            VaultSpec(spend_delay=common_spend_delay, unvault_trigger_secret=10)
            for _ in range(3)
        ]

        for v in vaults:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults))
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        revault_amount = COIN
        # Construct the final unvault target; save a coin to peel off in the revault.
        unvault_total_sats = sum(
            v.total_amount_sats for v in vaults) - revault_amount  # type: ignore
        assert unvault_total_sats > 0
        target_key = key.ECKey(secret=(1).to_bytes(32, "big"))

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=unvault_total_sats,
                   scriptPubKey=make_segwit0_spk(target_key))
        ]
        unvault_spec = UnvaultSpec(vaults, final_target_vout, revault_amount_sats=revault_amount)
        unvault_tx = get_trigger_tx([unvault_spec])

        badbehavior = [
            BadRevaultLowAmount,
            BadRevaultHighAmount,
        ]
        for bb in badbehavior:
            self.log.info("  bad tx: %s", bb.desc)
            bad_spec = UnvaultSpec(
                vaults, final_target_vout,
                revault_amount_sats=revault_amount, bad_behavior={bb})
            bad_tx = get_trigger_tx([bad_spec])
            self.assert_broadcast_tx(bad_tx, err_msg=bb.err)

        unvault_tx = get_trigger_tx([unvault_spec])
        txid = self.assert_broadcast_tx(unvault_tx, mine_all=True)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(txid), byteorder="big"), n=0)

        final_tx = get_final_withdrawal_tx(unvault_outpoint, unvault_spec)

        self.assert_broadcast_tx(final_tx, err_msg="non-BIP68-final")

        revault_spec = copy.deepcopy(vaults[0])
        revault_spec.total_amount_sats = revault_amount
        revault_spec.vault_output = unvault_tx.vout[1]
        revault_spec.vault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(txid), byteorder="big"), n=1)

        revault_unvault_spec = UnvaultSpec([revault_spec], [])
        revault_unvault_tx = get_trigger_tx([revault_unvault_spec])
        # The revault output should be immediately spendable into an OP_UNVAULT
        # output.
        self.assert_broadcast_tx(revault_unvault_tx, mine_all=True)

        self.generate(node, common_spend_delay)

        # Finalize the batch withdrawal.
        self.assert_broadcast_tx(final_tx, mine_all=True)

    def test_unauthed_recovery(self, node, wallet):
        """
        Test rules specific to unauthenticated recoveries.
        """
        # Create some vaults with the same unvaulting key, recovery key, but different
        # spend delays.
        recovery_auth = NoRecoveryAuth()
        vaults = [
            VaultSpec(spend_delay=i, recovery_auth=recovery_auth) for i in [10, 11, 200]
        ]

        # Ensure that vaults with different recovery keys can be swept in the same
        # transaction, using the same fee management.
        vault_diff_recovery = VaultSpec(
            recovery_secret=(DEFAULT_RECOVERY_SECRET + 10),
            recovery_auth=recovery_auth,
        )

        for v in vaults + [vault_diff_recovery]:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        assert vaults[0].vault_outpoint
        assert vaults[1].vault_outpoint
        assert vaults[2].vault_outpoint
        assert vault_diff_recovery.vault_outpoint

        outpoint_map = {
            vaults[0]: vaults[0].vault_outpoint,
            vaults[1]: vaults[1].vault_outpoint,
            vaults[2]: vaults[2].vault_outpoint,
            vault_diff_recovery: vault_diff_recovery.vault_outpoint,
        }

        bad1 = get_recovery_tx(outpoint_map)

        # Will fail due to extra recovery-incompatible vault input.
        self.assert_broadcast_tx(bad1, err_msg='recovery transaction has bad output structure')

        outpoint_map.pop(vault_diff_recovery)

        bad2 = get_recovery_tx(outpoint_map, fee_wallet=wallet)

        # Will fail due to extra non-vault fee input.
        self.assert_broadcast_tx(bad2, err_msg='recovery transaction has bad output structure')

        mutator = vout_amount_mutator(0, -1)
        bad3 = get_recovery_tx(outpoint_map, presig_tx_mutator=mutator)
        self.assert_broadcast_tx(bad3, err_msg='vault-insufficient-recovery-value')

        # Finally okay - and note that we can include an unrelated input that contributes
        # solely to fees.
        bad4 = get_recovery_tx(
            outpoint_map, fee_wallet=wallet, fee_coin_amount_sats=10_000)
        bad4.vout = bad4.vout[0:2]  # Include fee-change output and recovery output

        assert_equal(len(bad4.vout), 2)
        assert_equal(len(bad4.vin), 4)
        self.assert_broadcast_tx(bad4, err_msg='recovery transaction has bad output structure')

        # Finally okay - and note that we can include an unrelated input that contributes
        # solely to fees.
        good_tx = get_recovery_tx(
            outpoint_map, fee_wallet=wallet, fee_just_input=True, fee_coin_amount_sats=10_000)

        assert_equal(len(good_tx.vout), 2)
        assert_equal(len(good_tx.vin), 4)
        self.assert_broadcast_tx(good_tx, mine_all=True)

    def test_authed_recovery_witness_check(self, node, wallet, recovery_auth: RecoveryAuthorization):
        """
        Ensure that authorized recoveries actually check signatures.
        """
        vaults = [
            VaultSpec(spend_delay=i, recovery_auth=recovery_auth) for i in [10, 11, 200]
        ]

        # Ensure that vaults with different recovery keys can be swept in the same
        # transaction, using the same fee management.
        vault_diff_recovery = VaultSpec(
            recovery_secret=(DEFAULT_RECOVERY_SECRET + 10),
            recovery_auth=recovery_auth,
        )

        for v in vaults + [vault_diff_recovery]:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Start unvaulting the first vault.
        first_unvault_spec = UnvaultSpec([vaults[0]], [])
        unvault1_tx = get_trigger_tx([first_unvault_spec])
        unvault1_txid = unvault1_tx.rehash()
        assert_equal(
            node.sendrawtransaction(unvault1_tx.serialize().hex()), unvault1_txid,
        )

        XXX_mempool_fee_hack_for_no_pkg_relay(node, unvault1_txid)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # So now, 1 vault is in the process of unvaulting and the other two are still
        # vaulted. Recover them all with one transaction.
        unvault1_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(unvault1_txid), byteorder="big"), n=0
        )
        assert vaults[1].vault_outpoint
        assert vaults[2].vault_outpoint
        assert vault_diff_recovery.vault_outpoint

        outpoint_map = {
            vaults[0]: unvault1_outpoint,
            vaults[1]: vaults[1].vault_outpoint,
            vaults[2]: vaults[2].vault_outpoint,
            vault_diff_recovery: vault_diff_recovery.vault_outpoint,
        }

        recov_tx = get_recovery_tx(outpoint_map, unvault1_tx, fee_wallet=wallet)

        # Perturb the input nSequence, disrupting the signature, but skip the fee input (last).
        for inp_index in range(len(recov_tx.vin) - 1):
            recov_tx.vin[inp_index].nSequence += 1
            self.assert_broadcast_tx(recov_tx, err_msg='Invalid Schnorr sig')

            # Reset all inputs to RBFable.
            for reset_index in range(len(recov_tx.vin)):
                recov_tx.vin[reset_index].nSequence = 0

    def test_nonreplaceable_recovery(
        self,
        node,
        wallet,
        recovery_auth: RecoveryAuthorization,
    ):
        """
        Ensure that recovery transactions (of any kind) are always replaceable.
        """
        # Create some vaults with the same unvaulting key, recovery key, but different
        # spend delays.
        vaults = [
            VaultSpec(spend_delay=i, recovery_auth=recovery_auth) for i in [10, 11, 200]
        ]

        for v in vaults:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults))
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Start unvaulting the first vault.
        first_unvault_spec = UnvaultSpec([vaults[0]], [])
        unvault1_tx = get_trigger_tx([first_unvault_spec])
        unvault1_txid = unvault1_tx.rehash()
        assert_equal(
            node.sendrawtransaction(unvault1_tx.serialize().hex()), unvault1_txid,
        )

        XXX_mempool_fee_hack_for_no_pkg_relay(node, unvault1_txid)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # So now, 1 vault is in the process of unvaulting and the other two are still
        # vaulted. Recover them all with one transaction.
        unvault1_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(unvault1_txid), byteorder="big"), n=0
        )

        assert vaults[1].vault_outpoint
        assert vaults[2].vault_outpoint

        outpoint_map = {
            vaults[0]: unvault1_outpoint,
            vaults[1]: vaults[1].vault_outpoint,
            vaults[2]: vaults[2].vault_outpoint,
        }

        def make_final(vin_index: int):
            def mutator(tx):
                tx.vin[vin_index].nSequence = messages.MAX_BIP125_RBF_SEQUENCE + 1
            return mutator

        for inp_index in range(len(outpoint_map)):
            bad_tx = get_recovery_tx(
                outpoint_map, unvault1_tx, presig_tx_mutator=make_final(inp_index))

            self.assert_broadcast_tx(
                bad_tx, err_msg='Vault recovery inputs must be replaceable')

        # Finally okay.
        recov_tx = get_recovery_tx(outpoint_map, unvault1_tx)
        self.assert_broadcast_tx(recov_tx, mine_all=True)

    def test_bad_spend_delay(self, node, wallet):
        """
        Test that a negative spend delay fails.
        """
        # Create some vaults with the same unvaulting key, recovery key, but different
        # spend delays.
        recovery_auth = NoRecoveryAuth()
        vault = VaultSpec(spend_delay=-50, recovery_auth=recovery_auth)

        init_tx = vault.get_initialize_vault_tx(wallet)
        self.assert_broadcast_tx(init_tx, mine_all=True)

        unvault_spec = UnvaultSpec([vault], [])
        start_unvault_tx = get_trigger_tx([unvault_spec])
        self.assert_broadcast_tx(start_unvault_tx, err_msg='invalid spend delay')

        # On the other hand, recovering works fine because it is an independent tapleaf.
        recovery_tx = get_recovery_tx({vault: vault.vault_outpoint})
        self.assert_broadcast_tx(recovery_tx, mine_all=True)

    def test_bad_vout_idx(self, node, wallet):
        # TODO
        pass

    def assert_broadcast_tx(
        self,
        tx: CTransaction,
        mine_all: bool = False,
        err_msg: t.Optional[str] = None
    ) -> str:
        """
        Broadcast a transaction and facilitate various assertions about how the
        broadcast went.
        """
        node = self.nodes[0]
        txhex = tx.serialize().hex()
        txid = tx.rehash()

        if not err_msg:
            assert_equal(node.sendrawtransaction(txhex), txid)
        else:
            assert_raises_rpc_error(
                -26, err_msg, node.sendrawtransaction, txhex,
            )

        if mine_all:
            XXX_mempool_fee_hack_for_no_pkg_relay(node, txid)
            self.generate(node, 1)
            assert_equal(node.getmempoolinfo()["size"], 0)

        return txid

    def test_all_bad_recovery_types(self, recovery_auth, *recov_params, **recov_kwargs):
        unique_bad = BadRecoveryAuth
        if type(recovery_auth) == NoRecoveryAuth:
            unique_bad = BadRecoveryNoAnchor

        for bb in [unique_bad,
                   BadRecoveryAmountLow,
                   BadRecoveryAmountHigh,
                   BadRecoveryVoutIdx,
                   BadRecoveryVoutIdxNoExist]:
            bad_tx = get_recovery_tx(*recov_params, bad_behavior={bb}, **recov_kwargs)
            self.log.info("  bad recovery tx: %s", bb.desc)
            try_also = None

            if bb in (BadRecoveryAmountLow, BadRecoveryAmountHigh) \
                    and len(recov_params[0]) > 1:
                # If we're batching and the amount is low, the error will come from
                # the deferred check, not inline script interpreter.
                try_also = 'vault-insufficient-recovery-value'
            elif bb == BadRecoveryVoutIdx and len(recov_params[0]) > 1:
                try_also = 'recovery transaction has bad output structure'

            try:
                self.assert_broadcast_tx(bad_tx, err_msg=bb.err)
            except Exception:
                try:
                    self.assert_broadcast_tx(bad_tx, err_msg=try_also)
                except Exception:
                    script.pprint_tx(bad_tx)
                    raise


def vout_amount_mutator(vout_idx, amount=1):
    def reducer(tx):
        # Have to copy the whole vout list, otherwise we're modifying CTxOut objects
        # and that modification persists into the VaultSpec object
        # (vs. just the transaction).
        tx.vout = copy.deepcopy(tx.vout)
        tx.vout[vout_idx].nValue += amount
    return reducer


def XXX_mempool_fee_hack_for_no_pkg_relay(node, txid: str):
    """
    XXX manually prioritizing the 0-fee trigger transaction is necessary because
    we aren't doing package relay here, so the block assembler (rationally?)
    isn't including the 0-fee transaction.
    """
    node.prioritisetransaction(txid=txid, fee_delta=COIN)


DEFAULT_RECOVERY_SECRET = 2
DEFAULT_UNVAULT_SECRET = 3


class NoRecoveryAuth(RecoveryAuthorization):
    script = CScript()


class ChecksigRecoveryAuth(RecoveryAuthorization):

    def __init__(self) -> None:
        self.key = key.ECKey(secret=DEFAULT_RECOVERY_SECRET.to_bytes(32, 'big'))
        self.pubkey = key.compute_xonly_pubkey(self.key.get_bytes())[0]
        self.script = CScript([
            self.pubkey, script.OP_CHECKSIGVERIFY])

    def get_spend_wit_stack(
        self, tx_to: CTransaction, vin_idx: int, spent_outputs, recov_script: CScript,
        *args, **kwargs,
    ) -> t.List[bytes]:
        sigmsg = script.TaprootSignatureHash(
            tx_to, spent_outputs, input_index=vin_idx, hash_type=0,
            scriptpath=True, script=recov_script,
        )
        sig = key.sign_schnorr(self.key.get_bytes(), sigmsg)
        return [sig]


class VaultSpec:
    """
    A specification for a single vault UTXO that consolidates the context needed to
    unvault or recover.
    """
    def __init__(
        self,
        recovery_secret: t.Optional[int] = None,
        unvault_trigger_secret: t.Optional[int] = None,
        spend_delay: int = 10,
        recovery_auth: RecoveryAuthorization = NoRecoveryAuth(),
    ):
        self.recovery_key = key.ECKey(
            secret=(recovery_secret or DEFAULT_RECOVERY_SECRET).to_bytes(32, 'big'))
        # Taproot info for the recovery key.
        self.recovery_tr_info = taproot_from_privkey(self.recovery_key)

        # The sPK that needs to be satisfied in order to sweep to the recovery path.
        self.recovery_auth = recovery_auth
        self.recovery_hash: bytes = recovery_spk_tagged_hash(
            self.recovery_tr_info.scriptPubKey)

        # Use a basic key-path TR spend to trigger an unvault attempt.
        self.unvault_key = key.ECKey(
            secret=(
                unvault_trigger_secret or DEFAULT_UNVAULT_SECRET).to_bytes(32, 'big'))

        self.spend_delay = spend_delay

        self.recover_script = recovery_auth.script + CScript([
            self.recovery_hash, OP_VAULT_RECOVER,
        ])

        self.unvault_xonly_pubkey = key.compute_xonly_pubkey(self.unvault_key.get_bytes())[0]
        self.trigger_script = CScript([
            self.unvault_xonly_pubkey, script.OP_CHECKSIGVERIFY,
            self.spend_delay, OP_VAULT,
        ])

        # The initializing taproot output is either spendable via OP_VAULT
        # (script-path spend) or directly by the recovery key (key-path spend).
        self.init_tr = taproot_from_privkey(
            self.recovery_key, scripts=[
                ("recover", self.recover_script),
                ("trigger", self.trigger_script),
            ],
        )

        self.recover_spend_wit_fragment = [
            self.recover_script,
            self.init_tr.controlblock_for_script_spend("recover"),
        ]

        # Set when the vault is initialized.
        self.total_amount_sats: t.Optional[int] = None

        # Outpoint for spending the initialized vault.
        self.vault_outpoint: t.Optional[messages.COutPoint] = None
        self.vault_output: t.Optional[CTxOut] = None

    def get_initialize_vault_tx(
        self,
        wallet: MiniWallet,
        fees: t.Optional[int] = None,
    ) -> CTransaction:
        """
        Pull a UTXO from the wallet instance and spend it into the vault.

        The vault is spendable by either the usual means (unvault or recovery) via
        script-path spend, or immediately spendable by the recovery key via
        key-path spend.
        """
        utxo, utxo_in = wallet.get_utxo_as_txin()
        fees = fees if fees is not None else 10_000
        self.total_amount_sats = int(utxo["value"] * COIN) - fees

        self.vault_output = CTxOut(
            nValue=self.total_amount_sats,
            scriptPubKey=self.init_tr.scriptPubKey
        )
        vault_init = CTransaction()
        vault_init.nVersion = 2
        vault_init.vin = [utxo_in]
        vault_init.vout = [self.vault_output]

        # Cache the vault outpoint for later use during spending.
        self.vault_outpoint = messages.COutPoint(
            hash=int.from_bytes(bytes.fromhex(vault_init.rehash()), byteorder="big"),
            n=0
        )
        return vault_init


# Passed for <recovery-vout-idx> to signal that this spending transaction is not
# a recovery. For use on the witness stack, not in script.
NOT_A_RECOVERY_FLAG = script.bn2vch(-1)


class UnvaultTriggerTransaction(CTransaction):
    """
    Used to track metadata about an unvault trigger transaction to make generating
    the final withdrawal transaction easier.
    """
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # These are set after the transaction has been fully generated.
        self.unvault_specs: t.List[UnvaultSpec] = []

    @property
    def max_spend_delay(self) -> int:
        assert self.unvault_specs
        return max(spec.spend_delay for spec in self.unvault_specs)


# Used to make the OP_UNVAULT output only script-path spendable.
# See `VAULT_NUMS_INTERNAL_PUBKEY` in script/interpreter.cpp.
UNVAULT_NUMS_INTERNAL_PUBKEY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


class BadBehavior(t.NamedTuple):
    desc: str
    err: str


BadTriggerRecoveryPath = BadBehavior(
    "trigger with bad recovery path", "Trigger outputs not compatible")
BadTriggerSpendDelay = BadBehavior(
    "trigger with bad spend delay", "Trigger outputs not compatible")
BadTriggerAmountLow = BadBehavior(
    "trigger with low amount", "Trigger outputs not compatible")
BadTriggerAmountHigh = BadBehavior(
    "trigger with high amount", "bad-txns-in-belowout")
BadTriggerWithdrawOpcode = BadBehavior(
    "trigger with bad withdraw script", "Trigger outputs not compatible")
BadTriggerRecoverOpcode = BadBehavior(
    "trigger with bad recover script", "Trigger outputs not compatible")

BadRevaultLowAmount = BadBehavior(
    "bad revault amount (low)", "vault-insufficient-trigger-value")
BadRevaultHighAmount = BadBehavior(
    "bad revault amount (high)", "bad-txns-in-belowout")

BadRecoveryAmountLow = BadBehavior(
    "bad recovery amount (low)", "recovery output nValue too low")
BadRecoveryAmountHigh = BadBehavior(
    "bad recovery amount (high)", "bad-txns-in-belowout")
BadRecoveryAuth = BadBehavior("bad recovery auth wit", "Invalid Schnorr signature")
BadRecoveryNoAnchor = BadBehavior("no anchor for recov", "recovery transaction has bad output structure")
BadRecoveryVoutIdx = BadBehavior("incorrect recovery vout idx", "Invalid vault vout index given")
BadRecoveryVoutIdxNoExist = BadBehavior("nonexistent recovery vout idx", "Invalid vault vout index given")


def get_recovery_tx(
    vaults_to_outpoints: t.Dict[VaultSpec, messages.COutPoint],
    unvault_trigger_tx: t.Optional[UnvaultTriggerTransaction] = None,
    fee_wallet: t.Optional[MiniWallet] = None,
    fee_coin_amount_sats: t.Optional[int] = None,
    fee_just_input: bool = False,
    presig_tx_mutator: t.Optional[t.Callable] = None,
    postsig_tx_mutator: t.Optional[t.Callable] = None,
    bad_behavior: t.Optional[t.Set[BadBehavior]] = None,
) -> CTransaction:
    """
    Generate a transaction that recovers the vaults to their shared recovery path, either
    from an OP_VAULT output or an OP_UNVAULT output, from the pairing
    outpoints.

    If we're recovering from an OP_UNVAULT trigger output, we need the TaprootInfo which
    accompanies `unvault_trigger_tx`.
    """
    bad_behavior = bad_behavior or set()
    vaults = list(vaults_to_outpoints.keys())

    compat_vaults = defaultdict(list)
    vault_totals: t.Any = Counter()
    vault_to_taproot  = {}
    vault_to_recov_output_index = {}

    for v in vaults:
        recov_tr = v.recovery_tr_info
        compat_vaults[recov_tr].append(v)
        assert v.total_amount_sats
        vault_totals[recov_tr] += v.total_amount_sats
        vault_to_taproot[v] = recov_tr

    recovery_tx = CTransaction()
    recovery_tx.nVersion = 2
    recovery_tx.vin = [
        CTxIn(vaults_to_outpoints[v]) for v in vaults
    ]

    recovery_tx.vout = []
    spent_outputs: t.List[CTxOut] = []
    vault_to_spent_output = {}

    for v in vaults:
        # If this vault uses the optional recovery authorization, push the necessary
        # witness data into the stack.
        spent_output = v.vault_output
        vault_outpoint = vaults_to_outpoints[v]
        recovering_from_vaulted = vault_outpoint == v.vault_outpoint
        if not recovering_from_vaulted:
            assert unvault_trigger_tx
            spent_output = unvault_trigger_tx.vout[0]
        assert isinstance(spent_output, CTxOut)
        vault_to_spent_output[v] = spent_output
        spent_outputs.append(spent_output)

    for i, (recov_tr_info, amount) in enumerate(vault_totals.items()):
        if i == 0:
            if BadRecoveryAmountLow in bad_behavior:
                amount -= 1
            elif BadRecoveryAmountHigh in bad_behavior:
                amount += 1

        recovery_tx.vout.append(CTxOut(
            nValue=amount, scriptPubKey=recov_tr_info.scriptPubKey))

        for v, tr in vault_to_taproot.items():
            if tr == recov_tr_info:
                vault_to_recov_output_index[v] = i


    if fee_wallet:
        if fee_coin_amount_sats:
            tx = fee_wallet.send_self_transfer_multi(
                from_node=fee_wallet._test_node, amount_per_output=fee_coin_amount_sats)
            fee_utxo = fee_wallet.get_utxo_as_txin(txid=tx['txid'])
        else:
            fee_utxo = fee_wallet.get_utxo_as_txin()
        utxo = fee_utxo[0]
        FEE_IN_SATS = 10_000
        recovery_tx.vin.append(fee_utxo[1])
        val = int(utxo['value'] * COIN)

        if not fee_just_input:
            recovery_tx.vout.insert(0, CTxOut(
                nValue=(val - FEE_IN_SATS),
                scriptPubKey=CScript([script.OP_TRUE]),
            ))

            # Bump all vout indexes since we've inserted one before.
            for v in vault_to_recov_output_index:
                vault_to_recov_output_index[v] += 1

        spent_outputs.append(CTxOut(
            nValue=val, scriptPubKey=fee_wallet._scriptPubKey))

    if BadRecoveryNoAnchor not in bad_behavior:
        # Attach an ephemeral anchor output.
        recovery_tx.vout.append(CTxOut(nValue=0, scriptPubKey=CScript([script.OP_2])))

    if presig_tx_mutator:
        presig_tx_mutator(recovery_tx)


    for i, vault in enumerate(vaults):
        wit_fragment = []
        witness = messages.CTxInWitness()
        recovery_tx.wit.vtxinwit += [witness]
        vault_outpoint = vaults_to_outpoints[vault]
        recovering_from_vaulted = vault_outpoint == vault.vault_outpoint
        auth_wit_fragment = vault.recovery_auth.get_spend_wit_stack(
            recovery_tx, i, spent_outputs, vault.recover_script)

        if BadRecoveryAuth in bad_behavior:
            auth_wit_fragment[0] = auth_wit_fragment[0][::-1]

        if recovering_from_vaulted:
            wit_fragment = copy.deepcopy(vault.recover_spend_wit_fragment)

        # Otherwise, we're recovering away from an OP_UNVAULT trigger transaction.
        elif unvault_trigger_tx:
            for spec in unvault_trigger_tx.unvault_specs:
                if vault in spec.compat_vaults:
                    # Have to make a copy to avoid modifying the spec for future
                    # usages.
                    wit_fragment = copy.deepcopy(spec.recover_spend_wit_fragment)
        else:
            raise ValueError(
                "must pass `unvault_trigger_tx` if spending from unvault")

        assert wit_fragment is not None
        recov_vout_idx = vault_to_recov_output_index[vault]

        if BadRecoveryVoutIdx in bad_behavior:
            recov_vout_idx -= 1
        elif BadRecoveryVoutIdxNoExist in bad_behavior:
            recov_vout_idx = len(recovery_tx.vout) + 1

        witness.scriptWitness.stack = [
            script.bn2vch(recov_vout_idx),
            *auth_wit_fragment,
            *wit_fragment,
        ]

    if postsig_tx_mutator:
        postsig_tx_mutator(recovery_tx)

    return recovery_tx


class UnvaultSpec:
    """
    Gathers parameters for an unvault operation across potentially
    many vaults with compatible unvault parameters (i.e. shared recovery and delay).
    """
    def __init__(
        self,
        compat_vaults: t.List[VaultSpec],
        target_vout: t.List[CTxOut],
        revault_amount_sats: t.Optional[int] = None,
        bad_behavior: t.Optional[t.Set[BadBehavior]] = None,
    ) -> None:
        self.compat_vaults = compat_vaults
        self.revault_amount_sats = revault_amount_sats
        self.spend_delay = self.compat_vaults[0].spend_delay
        self.bad_behavior = bad_behavior or set()

        if BadTriggerSpendDelay in self.bad_behavior:
            self.spend_delay += 1

        # This is TEST-ONLY behavior - flip the spend delay non-negative if necessary
        # so that we can test failure for negative delays. Otherwise CTV hash fails.
        ctv_nsequence = self.spend_delay if self.spend_delay >= 0 else 1

        self.target_vout = target_vout
        withdraw_template = CTransaction()
        withdraw_template.nVersion = 2
        withdraw_template.vin = [CTxIn(nSequence=ctv_nsequence)]
        withdraw_template.vout = self.target_vout

        self.withdrawal_template = withdraw_template
        self.target_hash = self.withdrawal_template.get_standard_template_hash(0)

        self.withdraw_script: t.Union[CScript, bytes] = CScript([
            self.spend_delay, script.OP_CHECKSEQUENCEVERIFY, script.OP_DROP,
            self.target_hash, script.OP_CHECKTEMPLATEVERIFY,
        ])
        example_vault = self.compat_vaults[0]

        if BadTriggerWithdrawOpcode in self.bad_behavior:
            self.withdraw_script = self.withdraw_script[:-1] + CScript([script.OP_TRUE])

        recover_script = example_vault.recover_script

        if BadTriggerRecoveryPath in self.bad_behavior:
            recover_script = (
                recover_script[:-4] + b'\x00\x00\x00' + CScript([OP_VAULT_RECOVER]))

        if BadTriggerRecoverOpcode in self.bad_behavior:
            recover_script = recover_script[:-1] + CScript([OP_VAULT])

        self.trigger_tr = taproot_from_privkey(
            example_vault.recovery_key,
            scripts=[
                ('recover', recover_script),
                ('withdraw', self.withdraw_script),
            ])

        self.trigger_spk = self.trigger_tr.scriptPubKey

        self.amount = sum(v.total_amount_sats for v in self.compat_vaults)  # type: ignore

        if BadTriggerAmountLow in self.bad_behavior:
            self.amount -= 1
        if BadTriggerAmountHigh in self.bad_behavior:
            self.amount += 1

        if self.revault_amount_sats:
            self.amount -= self.revault_amount_sats

        self.trigger_txout = CTxOut(nValue=self.amount, scriptPubKey=self.trigger_spk)

        self.revault_txout = None
        if self.revault_amount_sats:
            vault_output = self.compat_vaults[0].vault_output
            assert vault_output

            if BadRevaultLowAmount in self.bad_behavior:
                self.revault_amount_sats -= 1
            if BadRevaultHighAmount in self.bad_behavior:
                self.revault_amount_sats += 1

            self.revault_txout = CTxOut(
                nValue=self.revault_amount_sats,
                scriptPubKey=vault_output.scriptPubKey)

        # Cache the taproot info for later use when constructing a spend.
        self.withdraw_spend_wit_fragment = [
            self.withdraw_script,
            self.trigger_tr.controlblock_for_script_spend("withdraw"),
        ]
        self.recover_spend_wit_fragment = [
            example_vault.recover_script,
            self.trigger_tr.controlblock_for_script_spend("recover"),
        ]
        self.vault_outpoints = [v.vault_outpoint for v in self.compat_vaults]
        self.vault_outputs = [v.vault_output for v in self.compat_vaults]

        # Set during trigger
        self.withdrawl_template: t.Optional[CTransaction] = None


def get_trigger_tx(
    unvault_trigger_specs: t.List[UnvaultSpec],
    fee_wallet: t.Optional[MiniWallet] = None,
    presig_tx_mutator: t.Optional[t.Callable] = None,
    postsig_tx_mutator: t.Optional[t.Callable] = None,
) -> UnvaultTriggerTransaction:
    """
    Return a transaction that triggers the withdrawal process to some arbitrary
    target output set.

    Args:
        revault_amount_sats (int): if given, "peel off" this amount from the
            total vault value to be revaulted.
    """
    trigger_tx = UnvaultTriggerTransaction()
    trigger_tx.unvault_specs = unvault_trigger_specs
    trigger_tx.nVersion = 2
    trigger_tx.vin = []
    trigger_tx.vout = []
    vault_outputs = []
    vaults_to_spec = {}
    vout_idx = 0
    revault_vout_idx = -1
    spec_to_vout_idx = {}

    for spec in unvault_trigger_specs:
        for vault in spec.compat_vaults:
            vaults_to_spec[vault] = spec

        trigger_tx.vin.extend(
            CTxIn(outpoint=outpoint) for outpoint in spec.vault_outpoints)
        trigger_tx.vout.append(spec.trigger_txout)

        spec_to_vout_idx[spec] = vout_idx
        vout_idx += 1

        if spec.revault_txout:
            trigger_tx.vout.append(spec.revault_txout)
            revault_vout_idx = vout_idx
            vout_idx += 1

        vault_outputs.extend(spec.vault_outputs)

    if fee_wallet:
        FEE_IN_SATS = 10_000
        fee_utxo = fee_wallet.get_utxo_as_txin()
        trigger_tx.vin.append(fee_utxo[1])
        trigger_tx.vout.insert(0, CTxOut(
            nValue=(int(fee_utxo[0]['value'] * COIN) - FEE_IN_SATS),
            scriptPubKey=CScript([script.OP_TRUE]),
        ))

        for k in spec_to_vout_idx:
            spec_to_vout_idx[k] += 1

    if presig_tx_mutator:
        presig_tx_mutator(trigger_tx)

    # Sign the input for each vault and attach a fitting witness.
    for i, (vault, spec) in enumerate(vaults_to_spec.items()):
        unvault_sigmsg = script.TaprootSignatureHash(
            trigger_tx, vault_outputs, input_index=i, hash_type=0,
            scriptpath=True, script=vault.trigger_script,
        )
        unvault_signature = key.sign_schnorr(
            vault.unvault_key.get_bytes(), unvault_sigmsg)

        trigger_vout_idx = spec_to_vout_idx[spec]

        trigger_tx.wit.vtxinwit += [messages.CTxInWitness()]
        trigger_tx.wit.vtxinwit[i].scriptWitness.stack = [
            script.bn2vch(revault_vout_idx),
            CScript([trigger_vout_idx]) if trigger_vout_idx != 0 else b'',
            spec.target_hash,
            unvault_signature,
            vault.trigger_script,
            vault.init_tr.controlblock_for_script_spend("trigger"),
        ]

    if postsig_tx_mutator:
        postsig_tx_mutator(trigger_tx)

    return trigger_tx


def get_final_withdrawal_tx(
    unvault_outpoint: COutPoint,
    unvault_spec: UnvaultSpec,
) -> CTransaction:
    """
    Return the final transaction, withdrawing a balance to the specified target.
    """
    final_tx = copy.deepcopy(unvault_spec.withdrawal_template)
    final_tx.vin[0].prevout = unvault_outpoint
    final_tx.wit.vtxinwit += [messages.CTxInWitness()]
    final_tx.wit.vtxinwit[0].scriptWitness.stack = [
        *unvault_spec.withdraw_spend_wit_fragment,
    ]

    assert_equal(final_tx.get_standard_template_hash(0), unvault_spec.target_hash)
    return final_tx


def recovery_spk_tagged_hash(script: CScript) -> bytes:
    ser = messages.ser_string(script)
    return key.TaggedHash("VaultRecoverySPK", ser)


def unvault_spk_tagged_hash(script: CScript) -> bytes:
    ser = messages.ser_string(script)
    return key.TaggedHash("VaultTriggerSPK", ser)


def taproot_from_privkey(pk: key.ECKey, scripts=None) -> script.TaprootInfo:
    x_only, _ = key.compute_xonly_pubkey(pk.get_bytes())
    return script.taproot_construct(x_only, scripts=scripts)


def split_vault_value(total_val: int, num: int = 3) -> t.List[int]:
    """
    Return kind-of evenly split amounts that preserve the total value of the vault.
    """
    val_segment = total_val // num
    amts = []
    for _ in range(num - 1):
        amts.append(val_segment)
        total_val -= val_segment
    amts.append(total_val)
    return amts


def make_segwit0_spk(privkey: key.ECKey) -> CScript:
    return CScript([script.OP_0, script.hash160(privkey.get_pubkey().get_bytes())])


if __name__ == "__main__":
    VaultsTest().main()
