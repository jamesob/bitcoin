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
import random
import typing as t

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.wallet import MiniWallet, MiniWalletMode
from test_framework.script import CScript, OP_VAULT, OP_UNVAULT
from test_framework.messages import CTransaction, COutPoint, CTxOut, CTxIn, COIN
from test_framework.util import assert_equal, assert_raises_rpc_error

from test_framework import script, key, messages


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
                "-dustrelayfee=0",
            ]
        ]
        self.setup_clean_chain = True

    def run_test(self):
        wallet = MiniWallet(self.nodes[0], mode=MiniWalletMode.RAW_OP_TRUE)
        node = self.nodes[0]
        node.add_p2p_connection(P2PInterface())

        # Generate some matured UTXOs to spend into vaults.
        self.generate(wallet, 200)

        self.log.info("Testing normal vault spend")
        self.single_vault_test(node, wallet)

        self.log.info("Testing sweep-to-recovery from the vault")
        self.single_vault_test(node, wallet, sweep_from_vault=True)

        self.log.info("Testing sweep-to-recovery from the unvault trigger")
        self.single_vault_test(node, wallet, sweep_from_unvault=True)

        self.log.info("Testing a batch sweep operation across multiple vaults")
        self.test_batch_sweep(node, wallet)

        self.log.info("Testing a batch unvault")
        self.test_batch_unvault(node, wallet)

    def single_vault_test(
        self,
        node,
        wallet,
        sweep_from_vault: bool = False,
        sweep_from_unvault: bool = False,
    ):
        """
        Test the creation and spend of a single vault, optionally sweeping at various
        stages of the vault lifecycle.
        """
        assert_equal(node.getmempoolinfo()["size"], 0)

        vault = VaultSpec()
        vault_init_tx = vault.get_initialize_vault_tx(wallet)

        self.assert_broadcast_tx(node, vault_init_tx, mine_all=True)

        if sweep_from_vault:
            assert vault.vault_outpoint
            sweep_tx = get_sweep_to_recovery_tx({vault: vault.vault_outpoint})
            self.assert_broadcast_tx(node, sweep_tx, mine_all=True)

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

        target_out_hash = target_outputs_hash(final_target_vout)
        start_unvault_tx = get_trigger_unvault_tx(target_out_hash, [vault])

        bad_unvault_spk = CScript([
            # <recovery-spk-hash>
            bytes([0x01] * 32),
            # <spend-delay>
            vault.spend_delay,
            # <target-outputs-hash>
            target_out_hash,
            OP_UNVAULT,
        ])
        bad_unvault = copy.deepcopy(start_unvault_tx)
        bad_unvault.vout[0].scriptPubKey = bad_unvault_spk
        assert_invalid(bad_unvault, "OP_UNVAULT outputs not compatible", node)

        bad_unvault_spk = CScript([
            # <recovery-spk-hash>
            recovery_spk_tagged_hash(vault.recovery_tr_info.scriptPubKey),
            # <spend-delay>
            vault.spend_delay - 1,
            # <target-outputs-hash>
            target_out_hash,
            OP_UNVAULT,
        ])
        bad_unvault = copy.deepcopy(start_unvault_tx)
        bad_unvault.vout[0].scriptPubKey = bad_unvault_spk
        assert_invalid(bad_unvault, "OP_UNVAULT outputs not compatible", node)

        bad_unvault = copy.deepcopy(start_unvault_tx)
        bad_unvault.vout[0].nValue = start_unvault_tx.vout[0].nValue - 1
        assert_invalid(bad_unvault, "OP_UNVAULT outputs not compatible", node)

        start_unvault_txid = self.assert_broadcast_tx(node, start_unvault_tx)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(start_unvault_txid), byteorder="big"), n=0
        )

        if sweep_from_unvault:
            sweep_tx = get_sweep_to_recovery_tx({vault: unvault_outpoint})
            self.assert_broadcast_tx(node, sweep_tx, mine_all=True)
            return

        final_unvault = CTransaction()
        final_unvault.nVersion = 2
        final_unvault.vin = [
            CTxIn(outpoint=unvault_outpoint, nSequence=vault.spend_delay)
        ]
        final_unvault.vout = final_target_vout

        # Broadcasting before start_unvault is confirmed fails.
        self.assert_broadcast_tx(
            node, final_unvault, expect_error_msg="non-BIP68-final")

        XXX_mempool_fee_hack_for_no_pkg_relay(node, start_unvault_txid)

        # Generate almost past the timelock, but not quite.
        self.generate(wallet, vault.spend_delay - 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        self.assert_broadcast_tx(
            node, final_unvault, expect_error_msg="non-BIP68-final")

        self.generate(wallet, 1)

        # Generate bad nSequence values.
        final_bad = copy.deepcopy(final_unvault)
        final_bad.vin[0].nSequence = final_unvault.vin[0].nSequence - 1
        assert_invalid(final_bad, "timelock has not matured", node)

        # Generate bad amounts.
        final_bad = copy.deepcopy(final_unvault)
        final_bad.vout[0].nValue = final_unvault.vout[0].nValue - 1
        assert_invalid(final_bad, "target hash mismatch", node)

        # Finally the unvault completes.
        self.assert_broadcast_tx(node, final_unvault, mine_all=True)

    def test_batch_sweep(self, node, wallet):
        """
        Test generating multiple vaults and sweeping them to the recovery path in batch.

        One of the vaults has been triggered for withdrawal while the other two
        are still vaulted.
        """
        # Create some vaults with the same unvaulting key, recovery key, but different
        # spend delays.
        vaults = [
            VaultSpec(spend_delay=i) for i in [10, 11, 12]
        ]

        for v in vaults:
            init_tx = v.get_initialize_vault_tx(wallet)
            self.assert_broadcast_tx(node, init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults))
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Start unvaulting the first vault.
        unvault1_tx = get_trigger_unvault_tx(b'\x00' * 32, [vaults[0]])
        unvault1_txid = unvault1_tx.rehash()
        assert_equal(
            node.sendrawtransaction(unvault1_tx.serialize().hex()), unvault1_txid,
        )

        XXX_mempool_fee_hack_for_no_pkg_relay(node, unvault1_txid)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # So now, 1 vault is in the process of unvaulting and the other two are still
        # vaulted. Sweep them all with one transaction.
        unvault1_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(unvault1_txid), byteorder="big"), n=0
        )

        sweep_tx = get_sweep_to_recovery_tx({
            vaults[0]: unvault1_outpoint,
            vaults[1]: vaults[1].vault_outpoint,
            vaults[2]: vaults[2].vault_outpoint,
        })
        self.assert_broadcast_tx(node, sweep_tx, mine_all=True)

    def test_batch_unvault(self, node, wallet):
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
            self.assert_broadcast_tx(node, init_tx)

        assert_equal(node.getmempoolinfo()["size"], len(vaults) + 2)
        self.generate(wallet, 1)
        assert_equal(node.getmempoolinfo()["size"], 0)

        # Construct the final unvault target.
        unvault_total_sats = sum(v.total_amount_sats for v in vaults)
        assert unvault_total_sats > 0
        target_key = key.ECKey(secret=(1).to_bytes(32, "big"))

        # The final withdrawal destination for the vaulted funds.
        final_target_vout = [
            CTxOut(nValue=unvault_total_sats,
                   scriptPubKey=make_segwit0_spk(target_key))
        ]
        target_out_hash = target_outputs_hash(final_target_vout)

        # Ensure that we can't batch with incompatible OP_VAULTs.
        for incompat_vaults in [[vault_diff_recovery],
                                [vault_diff_delay],
                                [vault_diff_recovery, vault_diff_delay]]:
            failed_unvault = get_trigger_unvault_tx(
                target_out_hash, vaults + incompat_vaults,
            )
            self.assert_broadcast_tx(
                node, failed_unvault,
                expect_error_msg="OP_UNVAULT outputs not compatible")

        good_batch_unvault = get_trigger_unvault_tx(target_out_hash, vaults)
        good_txid = self.assert_broadcast_tx(node, good_batch_unvault, mine_all=True)

        unvault_outpoint = COutPoint(
            hash=int.from_bytes(bytes.fromhex(good_txid), byteorder="big"), n=0
        )
        finalized = CTransaction()
        finalized.nVersion = 2
        finalized.vin = [
            CTxIn(outpoint=unvault_outpoint, nSequence=common_spend_delay)
        ]
        finalized.vout = final_target_vout

        self.assert_broadcast_tx(
            node, finalized, expect_error_msg="non-BIP68-final")

        self.generate(node, common_spend_delay)

        # Finalize the batch withdrawal.
        self.assert_broadcast_tx(node, finalized, mine_all=True)

    def assert_broadcast_tx(
        self,
        node,
        tx: CTransaction,
        mine_all: bool = False,
        expect_error_msg: t.Optional[str] = None
    ) -> str:
        """
        Broadcast a transaction and facilitate various assertions about how the
        broadcast went.
        """
        txhex = tx.serialize().hex()
        txid = tx.rehash()

        if not expect_error_msg:
            assert_equal(node.sendrawtransaction(txhex), txid)
        else:
            assert_raises_rpc_error(
                -26, expect_error_msg, node.sendrawtransaction, txhex,
            )

        if mine_all:
            XXX_mempool_fee_hack_for_no_pkg_relay(node, txid)
            self.generate(node, 1)
            assert_equal(node.getmempoolinfo()["size"], 0)

        return txid


def XXX_mempool_fee_hack_for_no_pkg_relay(node, txid: str):
    """
    XXX manually prioritizing the 0-fee trigger transaction is necessary because
    we aren't doing package relay here, so the block assembler (rationally?)
    isn't including the 0-fee transaction.
    """
    node.prioritisetransaction(txid=txid, fee_delta=COIN)


DEFAULT_RECOVERY_SECRET = 2
DEFAULT_UNVAULT_SECRET = 3


class VaultSpec:
    """
    A specification for a single vault UTXO that consolidates the context needed to
    unvault or sweep.
    """
    def __init__(
        self,
        recovery_secret: t.Optional[int] = None,
        unvault_trigger_secret: t.Optional[int] = None,
        spend_delay: int = 10,
    ):
        self.recovery_key = key.ECKey(
            secret=(recovery_secret or DEFAULT_RECOVERY_SECRET).to_bytes(32, 'big'))
        # Taproot info for the recovery key.
        self.recovery_tr_info = taproot_from_privkey(self.recovery_key)

        # Use a basic key-path TR spend to trigger an unvault attempt.
        self.unvault_key = key.ECKey(
            secret=(
                unvault_trigger_secret or DEFAULT_UNVAULT_SECRET).to_bytes(32, 'big'))
        self.unvault_tr_info = taproot_from_privkey(self.unvault_key)
        self.unvault_tweaked_privkey = key.tweak_add_privkey(
            self.unvault_key.get_bytes(), self.unvault_tr_info.tweak
        )
        assert isinstance(self.unvault_tweaked_privkey, bytes)

        self.spend_delay = spend_delay

        # The OP_VAULT scriptPubKey that is hidden in the initializing vault
        # outputs's script-path spend.
        self.vault_spk = CScript([
            # <recovery-spk-hash>
            recovery_spk_tagged_hash(self.recovery_tr_info.scriptPubKey),
            # <spend-delay>
            self.spend_delay,
            # <unvault-spk-hash>
            unvault_spk_tagged_hash(self.unvault_tr_info.scriptPubKey),
            OP_VAULT,
        ])

        # The initializing taproot output is either spendable via OP_VAULT
        # (script-path spend) or directly by the recovery key (key-path spend).
        self.init_tr_info = taproot_from_privkey(
            self.recovery_key, scripts=[("opvault", self.vault_spk)],
        )

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

        The vault is spendable by either the usual means (unvault or sweep) via
        script-path spend, or immediately spendable by the recovery key via
        key-path spend.
        """
        utxo, utxo_in = wallet.get_utxo_as_txin()
        fees = fees if fees is not None else int(10_000 * (random.random() + 0.2))
        self.total_amount_sats = int(utxo["value"] * COIN) - fees

        self.vault_output = CTxOut(
            nValue=self.total_amount_sats,
            scriptPubKey=self.init_tr_info.scriptPubKey
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


def get_sweep_to_recovery_tx(
    vaults_to_outpoints: t.Dict[VaultSpec, messages.COutPoint],
) -> CTransaction:
    """
    Generate a transaction that sweeps the vaults to their shared recovery path, either
    from an OP_VAULT output (TR) or an OP_UNVAULT output (bare), from the pairing
    outpoints.
    """
    vaults = list(vaults_to_outpoints.keys())
    total_vaults_amount_sats = sum(v.total_amount_sats for v in vaults)  # type: ignore

    sweep_tx = CTransaction()
    sweep_tx.nVersion = 2
    sweep_tx.vin = [
        CTxIn(vaults_to_outpoints[v]) for v in vaults
    ]
    sweep_tx.vout = [CTxOut(
        nValue=total_vaults_amount_sats,
        scriptPubKey=vaults[0].recovery_tr_info.scriptPubKey,
    )]

    for i, vault in enumerate(vaults):
        sweep_tx.wit.vtxinwit += [messages.CTxInWitness()]

        # If the outpoint we're spending isn't an OP_UNVAULT (i.e. if the unvault
        # process hasn't yet been triggered), then we need to reveal the vault via
        # script-path TR witness.
        if vaults_to_outpoints[vault] == vault.vault_outpoint:
            sweep_tx.wit.vtxinwit[i].scriptWitness.stack = [
                vault.vault_spk,
                (bytes([0xC0 + vault.init_tr_info.negflag])
                 + vault.init_tr_info.internal_pubkey),
            ]

    return sweep_tx


def get_trigger_unvault_tx(
    target_outputs_hash: bytes,
    vaults: t.List[VaultSpec],
) -> CTransaction:
    """
    Return a transaction that triggers the withdrawal process to some arbitrary
    target output set.
    """
    total_vaults_amount_sats = sum(v.total_amount_sats for v in vaults)  # type: ignore

    unvault_spk = CScript([
        # <recovery-spk-hash>
        recovery_spk_tagged_hash(vaults[0].recovery_tr_info.scriptPubKey),
        # <spend-delay>
        vaults[0].spend_delay,
        # <target-outputs-hash>
        target_outputs_hash,
        OP_UNVAULT,
    ])

    unvault_txout = CTxOut(nValue=total_vaults_amount_sats, scriptPubKey=unvault_spk)

    trigger_unvault = CTransaction()
    trigger_unvault.nVersion = 2
    trigger_unvault.vin = [CTxIn(outpoint=v.vault_outpoint) for v in vaults]
    trigger_unvault.vout = [unvault_txout]

    vault_outputs = [v.vault_output for v in vaults]

    # Sign the input for each vault and attach a fitting witness.
    for i, vault in enumerate(vaults):
        unvault_sigmsg = script.TaprootSignatureHash(
            trigger_unvault, vault_outputs, input_index=i, hash_type=0
        )

        assert isinstance(vault.unvault_tweaked_privkey, bytes)
        unvault_signature = key.sign_schnorr(
            vault.unvault_tweaked_privkey, unvault_sigmsg)

        trigger_unvault.wit.vtxinwit += [messages.CTxInWitness()]
        trigger_unvault.wit.vtxinwit[i].scriptWitness.stack = [
            unvault_signature,
            vault.unvault_tr_info.scriptPubKey,
            vault.vault_spk,
            (bytes([0xC0 + vault.init_tr_info.negflag])
             + vault.init_tr_info.internal_pubkey),
        ]

    return trigger_unvault


def assert_invalid(tx, msg, node):
    """
    Make a copy of the transaction, modify it, and ensure it fails to validate.
    """
    assert_raises_rpc_error(-26, msg, node.sendrawtransaction, tx.serialize().hex())


def recovery_spk_tagged_hash(script: CScript) -> bytes:
    ser = messages.ser_string(script)
    return key.TaggedHash("VaultRecoverySPK", ser)


def unvault_spk_tagged_hash(script: CScript) -> bytes:
    ser = messages.ser_string(script)
    return key.TaggedHash("VaultUnvaultSPK", ser)


def target_outputs_hash(vout: t.List[CTxOut]) -> bytes:
    """Equivalent to `PrecomputedTransactionData.hashOutputs`."""
    return messages.hash256(b"".join(v.serialize() for v in vout))


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
