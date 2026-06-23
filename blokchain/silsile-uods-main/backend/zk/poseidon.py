from __future__ import annotations

import hashlib
from typing import List

from .field import Fr, FIELD_MODULUS

T = 3
FULL_ROUNDS = 8
PARTIAL_ROUNDS = 57
TOTAL_ROUNDS = FULL_ROUNDS + PARTIAL_ROUNDS


def _grain_field_elements(seed: bytes, count: int) -> List[Fr]:
    out: List[Fr] = []
    counter = 0
    while len(out) < count:
        h = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        candidate = int.from_bytes(h, "big") % FIELD_MODULUS
        out.append(Fr(candidate))
        counter += 1
    return out


def _build_round_constants() -> List[List[Fr]]:
    flat = _grain_field_elements(b"UODS-Poseidon-RC-bn128-t3-v1", TOTAL_ROUNDS * T)
    return [flat[i * T : (i + 1) * T] for i in range(TOTAL_ROUNDS)]


def _build_mds() -> List[List[Fr]]:
    xs = _grain_field_elements(b"UODS-Poseidon-MDS-x-bn128-t3-v1", T)
    ys = _grain_field_elements(b"UODS-Poseidon-MDS-y-bn128-t3-v1", T)
    seen = set()
    for e in xs + ys:
        if e.v in seen:
            raise RuntimeError("MDS Cauchy matrisi icin x/y degerleri benzersiz olmali")
        seen.add(e.v)
    mds: List[List[Fr]] = []
    for i in range(T):
        row: List[Fr] = []
        for j in range(T):
            row.append((xs[i] + ys[j]).inv())
        mds.append(row)
    return mds


ROUND_CONSTANTS = _build_round_constants()
MDS = _build_mds()


def _sbox(x: Fr) -> Fr:
    x2 = x * x
    x4 = x2 * x2
    return x4 * x


def _mix(state: List[Fr]) -> List[Fr]:
    out: List[Fr] = []
    for i in range(T):
        acc = Fr(0)
        for j in range(T):
            acc = acc + MDS[i][j] * state[j]
        out.append(acc)
    return out


def poseidon_permutation(inputs: List[Fr]) -> List[Fr]:
    if len(inputs) != T:
        raise ValueError(f"Poseidon t={T} icin {T} eleman bekleniyor")
    state = [Fr(v) for v in inputs]
    half_full = FULL_ROUNDS // 2

    rc_index = 0
    for _ in range(half_full):
        state = [state[i] + ROUND_CONSTANTS[rc_index][i] for i in range(T)]
        state = [_sbox(s) for s in state]
        state = _mix(state)
        rc_index += 1

    for _ in range(PARTIAL_ROUNDS):
        state = [state[i] + ROUND_CONSTANTS[rc_index][i] for i in range(T)]
        state[0] = _sbox(state[0])
        state = _mix(state)
        rc_index += 1

    for _ in range(half_full):
        state = [state[i] + ROUND_CONSTANTS[rc_index][i] for i in range(T)]
        state = [_sbox(s) for s in state]
        state = _mix(state)
        rc_index += 1

    return state


def poseidon2(left, right) -> Fr:
    state = [Fr(0), Fr(left), Fr(right)]
    return poseidon_permutation(state)[0]


def poseidon_merkle_root(leaves: List, sibling_index_first: bool = False) -> Fr:
    if not leaves:
        raise ValueError("En az bir yaprak gerekli")
    level = [Fr(v) for v in leaves]
    while len(level) > 1:
        nxt: List[Fr] = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                a, b = level[i], level[i + 1]
                if int(a) <= int(b):
                    nxt.append(poseidon2(a, b))
                else:
                    nxt.append(poseidon2(b, a))
                i += 2
            else:
                nxt.append(level[i])
                i += 1
        level = nxt
    return level[0]
