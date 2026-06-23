# -*- coding: utf-8 -*-
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("eth_tester", reason="eth-tester kurulu degil")

from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

import zk
from zk.service import export_proof, export_vk_for_contract

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"


def _artifact(name):
    abi = json.loads((CONTRACTS / f"{name}.abi.json").read_text(encoding="utf-8"))
    bytecode = (CONTRACTS / f"{name}.bytecode.txt").read_text(encoding="utf-8").strip()
    return abi, bytecode


@pytest.fixture(scope="module")
def deployed():
    w3 = Web3(EthereumTesterProvider())
    owner = w3.eth.accounts[0]
    w3.eth.default_account = owner

    ver_abi, ver_bin = _artifact("Groth16Verifier")
    reg_abi, reg_bin = _artifact("OpticalFormRegistry")

    V = w3.eth.contract(abi=ver_abi, bytecode=ver_bin)
    vr = w3.eth.wait_for_transaction_receipt(V.constructor().transact())
    verifier = w3.eth.contract(address=vr.contractAddress, abi=ver_abi)

    R = w3.eth.contract(abi=reg_abi, bytecode=reg_bin)
    rr = w3.eth.wait_for_transaction_receipt(R.constructor().transact())
    registry = w3.eth.contract(address=rr.contractAddress, abi=reg_abi)

    zk_setup = zk.generate_zk_setup(depth=2)
    vk = export_vk_for_contract(zk_setup)
    w3.eth.wait_for_transaction_receipt(
        verifier.functions.setVerifyingKey(
            vk["alpha"], vk["beta"], vk["gamma"], vk["delta"], vk["ic"]
        ).transact()
    )
    w3.eth.wait_for_transaction_receipt(
        registry.functions.setZkVerifier(vr.contractAddress).transact()
    )
    return w3, owner, verifier, registry, zk_setup


@pytest.mark.slow
class TestOnChainZk:
    def test_valid_proof_accepted_on_chain(self, deployed):
        w3, owner, verifier, registry, zk_setup = deployed
        leaves = [zk.Fr(1000 + i) for i in range(3)]
        witness = zk.build_membership_witness(leaves, leaf_index=1, depth=2)
        proof = zk.prove_membership(zk_setup, witness)
        assert zk.verify_membership_locally(zk_setup, proof)

        zk_root = int(witness.root)
        keccak_root = Web3.keccak(text="zk-batch-A")
        w3.eth.wait_for_transaction_receipt(
            registry.functions.addBatchRootWithZk(keccak_root, 3, zk_root).transact()
        )
        assert registry.functions.zkRootExists(zk_root).call() is True

        sp = export_proof(proof)
        a = [int(x) for x in sp["a"]]
        b = [[int(x) for x in pair] for pair in sp["b"]]
        c = [int(x) for x in sp["c"]]
        pub = [int(x) for x in sp["public_inputs"]]
        assert registry.functions.verifyZkMembership(a, b, c, pub).call() is True

    def test_unregistered_root_rejected(self, deployed):
        w3, owner, verifier, registry, zk_setup = deployed
        leaves = [zk.Fr(5000 + i) for i in range(3)]
        witness = zk.build_membership_witness(leaves, leaf_index=0, depth=2)
        proof = zk.prove_membership(zk_setup, witness)
        sp = export_proof(proof)
        a = [int(x) for x in sp["a"]]
        b = [[int(x) for x in pair] for pair in sp["b"]]
        c = [int(x) for x in sp["c"]]
        pub = [int(x) for x in sp["public_inputs"]]
        with pytest.raises(Exception):
            registry.functions.verifyZkMembership(a, b, c, pub).call()

    def test_direct_verifier_rejects_tampered_proof(self, deployed):
        w3, owner, verifier, registry, zk_setup = deployed
        leaves = [zk.Fr(7000 + i) for i in range(3)]
        witness = zk.build_membership_witness(leaves, leaf_index=2, depth=2)
        proof = zk.prove_membership(zk_setup, witness)
        sp = export_proof(proof)
        a = [int(sp["a"][0]) + 1, int(sp["a"][1])]
        b = [[int(x) for x in pair] for pair in sp["b"]]
        c = [int(x) for x in sp["c"]]
        pub = [int(x) for x in sp["public_inputs"]]
        with pytest.raises(Exception):
            verifier.functions.verifyProof(a, b, c, pub).call()
