from __future__ import annotations

import json
import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .circuit import MembershipCircuit, compute_root_from_path
from .field import Fr
from .groth16 import (
    Proof,
    ProvingKey,
    VerifyingKey,
    prove,
    serialize_proof_to_dict,
    serialize_vk_for_solidity,
    serialize_vk_to_dict,
    setup,
    verify,
)
from .poseidon import poseidon2, poseidon_merkle_root


class ZKError(Exception):
    pass


DEFAULT_DEPTH = 10


def sha256_hex_to_fr(value_hex: str) -> Fr:
    cleaned = value_hex[2:] if value_hex.startswith("0x") else value_hex
    return Fr(int(cleaned, 16))


@dataclass
class ZKSetup:
    depth: int
    proving_key: ProvingKey
    verifying_key: VerifyingKey


def generate_zk_setup(depth: int = DEFAULT_DEPTH) -> ZKSetup:
    circuit = MembershipCircuit(depth=depth)
    leaf = Fr(1)
    siblings = [Fr(0)] * depth
    indices = [0] * depth
    root = compute_root_from_path(leaf, siblings, indices)
    r1cs, _, _ = circuit.build(root, leaf, siblings, indices)
    pk, vk = setup(r1cs)
    return ZKSetup(depth=depth, proving_key=pk, verifying_key=vk)


def save_setup(zk_setup: ZKSetup, directory) -> Tuple[Path, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    pk_path = directory / f"membership_pk_d{zk_setup.depth}.pkl"
    vk_path = directory / f"membership_vk_d{zk_setup.depth}.json"
    with open(pk_path, "wb") as f:
        pickle.dump(
            {
                "depth": zk_setup.depth,
                "proving_key": zk_setup.proving_key,
                "verifying_key": zk_setup.verifying_key,
            },
            f,
        )
    with open(vk_path, "w", encoding="utf-8") as f:
        json.dump(serialize_vk_to_dict(zk_setup.verifying_key), f, indent=2)
    return pk_path, vk_path


def load_setup(directory, depth: int = DEFAULT_DEPTH) -> Optional[ZKSetup]:
    directory = Path(directory)
    pk_path = directory / f"membership_pk_d{depth}.pkl"
    if not pk_path.exists():
        return None
    with open(pk_path, "rb") as f:
        data = pickle.load(f)
    return ZKSetup(
        depth=data["depth"],
        proving_key=data["proving_key"],
        verifying_key=data["verifying_key"],
    )


def load_or_generate_setup(directory, depth: int = DEFAULT_DEPTH) -> ZKSetup:
    existing = load_setup(directory, depth)
    if existing is not None:
        return existing
    zk_setup = generate_zk_setup(depth)
    save_setup(zk_setup, directory)
    return zk_setup


@dataclass
class MembershipWitness:
    root: Fr
    leaf: Fr
    path_elements: List[Fr]
    path_indices: List[int]


def build_poseidon_tree(leaves: List[Fr], depth: int):
    if len(leaves) > (1 << depth):
        raise ZKError(
            f"Yaprak sayisi ({len(leaves)}) derinlik {depth} kapasitesini ({1 << depth}) asiyor"
        )
    padded = list(leaves) + [Fr(0)] * ((1 << depth) - len(leaves))
    levels = [padded]
    current = padded
    while len(current) > 1:
        nxt: List[Fr] = []
        for i in range(0, len(current), 2):
            left, right = current[i], current[i + 1]
            nxt.append(poseidon2(left, right))
        levels.append(nxt)
        current = nxt
    return levels


def root_of_tree(levels) -> Fr:
    return levels[-1][0]


def build_membership_witness(
    leaves: List[Fr], leaf_index: int, depth: int
) -> MembershipWitness:
    if not (0 <= leaf_index < len(leaves)):
        raise ZKError(f"Gecersiz yaprak indeksi: {leaf_index}")
    levels = build_poseidon_tree(leaves, depth)
    path_elements: List[Fr] = []
    path_indices: List[int] = []
    index = leaf_index
    for level in range(depth):
        sibling_index = index ^ 1
        path_elements.append(levels[level][sibling_index])
        path_indices.append(index & 1)
        index >>= 1
    leaf = leaves[leaf_index]
    root = root_of_tree(levels)
    expected = compute_root_from_path(leaf, path_elements, path_indices)
    if expected != root:
        raise ZKError("Insa edilen tanik yol kok ile uyusmuyor (ic hata)")
    return MembershipWitness(
        root=root, leaf=leaf, path_elements=path_elements, path_indices=path_indices
    )


def prove_membership(zk_setup: ZKSetup, witness: MembershipWitness) -> Proof:
    circuit = MembershipCircuit(depth=zk_setup.depth)
    r1cs, full_witness, _ = circuit.build(
        witness.root, witness.leaf, witness.path_elements, witness.path_indices
    )
    if not r1cs.is_satisfied(full_witness):
        raise ZKError("Tanik devreyi saglamiyor; uyelik kaniti uretilemez")
    return prove(zk_setup.proving_key, r1cs, full_witness)


def verify_membership_locally(zk_setup: ZKSetup, proof: Proof) -> bool:
    return verify(zk_setup.verifying_key, proof)


def export_proof(proof: Proof) -> dict:
    return serialize_proof_to_dict(proof)


def export_vk_for_contract(zk_setup: ZKSetup) -> dict:
    return serialize_vk_for_solidity(zk_setup.verifying_key)
