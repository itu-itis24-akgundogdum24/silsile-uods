# -*- coding: utf-8 -*-
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from zk.circuit import MembershipCircuit, compute_root_from_path
from zk.field import FIELD_MODULUS, Fr
from zk.groth16 import (
    prove,
    serialize_proof_for_solidity,
    serialize_vk_for_solidity,
    setup,
    verify,
)
from zk.poseidon import poseidon2, poseidon_permutation
from zk.service import (
    MembershipWitness,
    ZKError,
    build_membership_witness,
    generate_zk_setup,
    load_setup,
    prove_membership,
    save_setup,
    verify_membership_locally,
)


class TestPoseidon:
    def test_deterministic(self):
        assert poseidon2(3, 5) == poseidon2(3, 5)

    def test_order_sensitive(self):
        assert poseidon2(3, 5) != poseidon2(5, 3)

    def test_permutation_diffusion(self):
        a = poseidon_permutation([Fr(0), Fr(0), Fr(0)])
        b = poseidon_permutation([Fr(0), Fr(0), Fr(1)])
        assert a[0] != b[0]

    def test_output_in_field(self):
        out = poseidon2(123456789, 987654321)
        assert 0 <= int(out) < FIELD_MODULUS


class TestMembershipCircuit:
    def test_valid_witness_satisfies(self):
        leaf = Fr(42)
        siblings = [Fr(7), Fr(8)]
        indices = [1, 0]
        root = compute_root_from_path(leaf, siblings, indices)
        r1cs, witness, public = MembershipCircuit(depth=2).build(
            root, leaf, siblings, indices
        )
        assert r1cs.is_satisfied(witness)
        assert len(public) == 1
        assert public[0] == root

    def test_wrong_leaf_fails(self):
        leaf = Fr(42)
        siblings = [Fr(7), Fr(8)]
        indices = [1, 0]
        root = compute_root_from_path(leaf, siblings, indices)
        r1cs, witness, _ = MembershipCircuit(depth=2).build(
            root, Fr(43), siblings, indices
        )
        assert not r1cs.is_satisfied(witness)

    def test_selector_must_be_boolean(self):
        leaf = Fr(42)
        siblings = [Fr(7)]
        root = compute_root_from_path(leaf, siblings, [1])
        r1cs, witness, _ = MembershipCircuit(depth=1).build(root, leaf, siblings, [1])
        tampered = list(witness)
        for idx in range(len(tampered)):
            if tampered[idx] == Fr(1):
                continue
        assert r1cs.is_satisfied(witness)


@pytest.mark.slow
class TestGroth16:
    @pytest.fixture(scope="class")
    def proven(self):
        leaf = Fr(777)
        siblings = [Fr(55)]
        indices = [1]
        root = compute_root_from_path(leaf, siblings, indices)
        r1cs, witness, _ = MembershipCircuit(depth=1).build(
            root, leaf, siblings, indices
        )
        pk, vk = setup(r1cs)
        proof = prove(pk, r1cs, witness)
        return pk, vk, proof, root

    def test_valid_proof_verifies(self, proven):
        _, vk, proof, _ = proven
        assert verify(vk, proof) is True

    def test_public_input_is_root(self, proven):
        _, _, proof, root = proven
        assert proof.public_inputs[0] == int(root) % FIELD_MODULUS

    def test_forged_public_input_rejected(self, proven):
        from zk.groth16 import Proof

        _, vk, proof, _ = proven
        forged = Proof(
            a=proof.a,
            b=proof.b,
            c=proof.c,
            public_inputs=[(proof.public_inputs[0] + 1) % FIELD_MODULUS],
        )
        assert verify(vk, forged) is False

    def test_serialization_structure(self, proven):
        _, vk, proof, _ = proven
        sp = serialize_proof_for_solidity(proof)
        sv = serialize_vk_for_solidity(vk)
        assert len(sp["a"]) == 2
        assert len(sp["b"]) == 2 and len(sp["b"][0]) == 2
        assert len(sp["c"]) == 2
        assert len(sv["ic"]) == sv["numPublic"]

    def test_solidity_pairing_equation_holds(self, proven):
        from py_ecc.optimized_bn128 import (
            FQ,
            FQ2,
            FQ12,
            Z1,
            add,
            multiply,
            neg,
            pairing,
        )

        _, vk, proof, _ = proven
        sp = serialize_proof_for_solidity(proof)
        sv = serialize_vk_for_solidity(vk)

        def g1(xy):
            x, y = xy
            if x == 0 and y == 0:
                return Z1
            return (FQ(x), FQ(y), FQ.one())

        def g2(pair):
            (x1, x0), (y1, y0) = pair
            return (FQ2([x0, x1]), FQ2([y0, y1]), FQ2.one())

        A = g1(sp["a"])
        B = g2(sp["b"])
        C = g1(sp["c"])
        alpha = g1(sv["alpha"])
        beta = g2(sv["beta"])
        gamma = g2(sv["gamma"])
        delta = g2(sv["delta"])
        ic = [g1(p) for p in sv["ic"]]

        vkx = ic[0]
        for i, val in enumerate(sp["publicInputs"]):
            vkx = add(vkx, multiply(ic[i + 1], val))

        prod = (
            pairing(B, neg(A))
            * pairing(beta, alpha)
            * pairing(gamma, vkx)
            * pairing(delta, C)
        )
        assert prod == FQ12.one()


@pytest.mark.slow
class TestZKService:
    @pytest.fixture(scope="class")
    def setup_obj(self):
        return generate_zk_setup(depth=2)

    def test_build_witness_and_prove(self, setup_obj):
        leaves = [Fr(100 + i) for i in range(3)]
        w = build_membership_witness(leaves, leaf_index=1, depth=2)
        proof = prove_membership(setup_obj, w)
        assert verify_membership_locally(setup_obj, proof) is True
        assert proof.public_inputs[0] == int(w.root) % FIELD_MODULUS

    def test_non_member_rejected(self, setup_obj):
        leaves = [Fr(100 + i) for i in range(3)]
        w = build_membership_witness(leaves, leaf_index=1, depth=2)
        forged = MembershipWitness(
            root=w.root,
            leaf=Fr(424242),
            path_elements=w.path_elements,
            path_indices=w.path_indices,
        )
        with pytest.raises(ZKError):
            prove_membership(setup_obj, forged)

    def test_save_and_load(self, setup_obj, tmp_path):
        save_setup(setup_obj, tmp_path)
        loaded = load_setup(tmp_path, depth=2)
        assert loaded is not None
        leaves = [Fr(5), Fr(6), Fr(7)]
        w = build_membership_witness(leaves, leaf_index=0, depth=2)
        proof = prove_membership(loaded, w)
        assert verify_membership_locally(loaded, proof) is True

    def test_capacity_overflow(self, setup_obj):
        leaves = [Fr(i) for i in range(5)]
        with pytest.raises(ZKError):
            build_membership_witness(leaves, leaf_index=0, depth=2)
