from __future__ import annotations

from typing import List

from .field import Fr
from .poseidon import (
    FULL_ROUNDS,
    MDS,
    PARTIAL_ROUNDS,
    ROUND_CONSTANTS,
    T,
)
from .r1cs import ConstraintSystem, LinComb


def _sbox_lc(cs: ConstraintSystem, x_lc: LinComb) -> LinComb:
    x2 = cs.mul(x_lc, x_lc)
    x4 = cs.mul(cs.wire_lc(x2), cs.wire_lc(x2))
    x5 = cs.mul(cs.wire_lc(x4), x_lc)
    return cs.wire_lc(x5)


def _mix_lc(cs: ConstraintSystem, state: List[LinComb]) -> List[LinComb]:
    out: List[LinComb] = []
    for i in range(T):
        terms = [(state[j], MDS[i][j]) for j in range(T)]
        out.append(cs.linear_combo(terms))
    return out


def poseidon_permutation_lc(cs: ConstraintSystem, state: List[LinComb]) -> List[LinComb]:
    half_full = FULL_ROUNDS // 2
    rc_index = 0

    for _ in range(half_full):
        state = [cs.add(state[i], cs.const_lc(ROUND_CONSTANTS[rc_index][i])) for i in range(T)]
        state = [_sbox_lc(cs, state[i]) for i in range(T)]
        state = _mix_lc(cs, state)
        rc_index += 1

    for _ in range(PARTIAL_ROUNDS):
        state = [cs.add(state[i], cs.const_lc(ROUND_CONSTANTS[rc_index][i])) for i in range(T)]
        state[0] = _sbox_lc(cs, state[0])
        state = _mix_lc(cs, state)
        rc_index += 1

    for _ in range(half_full):
        state = [cs.add(state[i], cs.const_lc(ROUND_CONSTANTS[rc_index][i])) for i in range(T)]
        state = [_sbox_lc(cs, state[i]) for i in range(T)]
        state = _mix_lc(cs, state)
        rc_index += 1

    return state


def poseidon2_lc(cs: ConstraintSystem, left_lc: LinComb, right_lc: LinComb) -> LinComb:
    state = [cs.const_lc(Fr(0)), left_lc, right_lc]
    return poseidon_permutation_lc(cs, state)[0]


def enforce_boolean(cs: ConstraintSystem, b_lc: LinComb) -> None:
    one_minus_b = cs.linear_combo([(cs.const_lc(Fr(1)), Fr(1)), (b_lc, Fr(-1))])
    cs.add_constraint(b_lc, one_minus_b, cs.const_lc(Fr(0)))


def conditional_swap_lc(cs: ConstraintSystem, cur_lc: LinComb, sib_lc: LinComb, sel_lc: LinComb):
    diff = cs.linear_combo([(sib_lc, Fr(1)), (cur_lc, Fr(-1))])
    t = cs.mul(sel_lc, diff)
    left = cs.add(cur_lc, cs.wire_lc(t))
    right = cs.linear_combo([(sib_lc, Fr(1)), (cs.wire_lc(t), Fr(-1))])
    return left, right
