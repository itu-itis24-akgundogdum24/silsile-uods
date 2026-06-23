from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from .field import Fr
from .gadgets import conditional_swap_lc, enforce_boolean, poseidon2_lc
from .poseidon import poseidon2
from .r1cs import ConstraintSystem, R1CS


def compute_root_from_path(leaf, path_elements: List, path_indices: List[int]):
    if len(path_elements) != len(path_indices):
        raise ValueError("path_elements ve path_indices ayni uzunlukta olmali")
    cur = Fr(leaf)
    for sib, sel in zip(path_elements, path_indices):
        sib = Fr(sib)
        if int(sel) not in (0, 1):
            raise ValueError("path index 0 veya 1 olmali")
        if int(sel) == 0:
            left, right = cur, sib
        else:
            left, right = sib, cur
        cur = poseidon2(left, right)
    return cur


@dataclass
class MembershipCircuit:
    depth: int

    def build(
        self,
        root: Fr,
        leaf: Fr,
        path_elements: List[Fr],
        path_indices: List[int],
    ) -> Tuple[R1CS, List[Fr], List[Fr]]:
        if len(path_elements) != self.depth or len(path_indices) != self.depth:
            raise ValueError(f"path uzunlugu derinlik ({self.depth}) ile uyusmali")

        cs = ConstraintSystem()
        root_wire = cs.alloc_public(Fr(root))
        root_lc = cs.wire_lc(root_wire)

        leaf_wire = cs.alloc(Fr(leaf))
        cur_lc = cs.wire_lc(leaf_wire)

        for level in range(self.depth):
            sib_wire = cs.alloc(Fr(path_elements[level]))
            sel_wire = cs.alloc(Fr(path_indices[level]))
            sel_lc = cs.wire_lc(sel_wire)
            enforce_boolean(cs, sel_lc)
            left_lc, right_lc = conditional_swap_lc(
                cs, cur_lc, cs.wire_lc(sib_wire), sel_lc
            )
            cur_lc = poseidon2_lc(cs, left_lc, right_lc)

        cs.enforce_equal(cur_lc, root_lc)

        r1cs, witness = cs.finalize()
        public_inputs = witness[1 : r1cs.num_public]
        return r1cs, witness, public_inputs


def build_membership_r1cs(depth: int) -> MembershipCircuit:
    return MembershipCircuit(depth=depth)
