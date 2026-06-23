from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .field import Fr

LinComb = Dict[int, Fr]


def _lc_add(a: LinComb, b: LinComb) -> LinComb:
    out: LinComb = dict(a)
    for wire, coeff in b.items():
        s = out.get(wire, Fr(0)) + coeff
        if s == Fr(0):
            out.pop(wire, None)
        else:
            out[wire] = s
    return out


def _lc_scale(a: LinComb, k: Fr) -> LinComb:
    if k == Fr(0):
        return {}
    return {wire: coeff * k for wire, coeff in a.items()}


def _lc_const(value: Fr) -> LinComb:
    if value == Fr(0):
        return {}
    return {0: value}


def _lc_eval(lc: LinComb, witness: List[Fr]) -> Fr:
    acc = Fr(0)
    for wire, coeff in lc.items():
        acc = acc + coeff * witness[wire]
    return acc


@dataclass
class R1CS:
    num_wires: int
    num_public: int
    constraints: List[Tuple[LinComb, LinComb, LinComb]]

    def is_satisfied(self, witness: List[Fr]) -> bool:
        if len(witness) != self.num_wires:
            raise ValueError(
                f"Taniklik uzunlugu {len(witness)} beklenen {self.num_wires} ile uyusmuyor"
            )
        for a, b, c in self.constraints:
            if _lc_eval(a, witness) * _lc_eval(b, witness) != _lc_eval(c, witness):
                return False
        return True


@dataclass
class ConstraintSystem:
    _next_wire: int = 1
    num_public: int = 1
    constraints: List[Tuple[LinComb, LinComb, LinComb]] = field(default_factory=list)
    _assignment: List[Fr] = field(default_factory=lambda: [Fr(1)])
    _public_locked: bool = False

    def alloc_public(self, value: Fr) -> int:
        if self._public_locked:
            raise RuntimeError("Tum public girisler private'tan once tahsis edilmeli")
        wire = self._next_wire
        self._next_wire += 1
        self.num_public += 1
        self._assignment.append(Fr(value))
        return wire

    def alloc(self, value: Fr) -> int:
        self._public_locked = True
        wire = self._next_wire
        self._next_wire += 1
        self._assignment.append(Fr(value))
        return wire

    def const_lc(self, value: Fr) -> LinComb:
        return _lc_const(Fr(value))

    def wire_lc(self, wire: int) -> LinComb:
        return {wire: Fr(1)}

    def add_constraint(self, a: LinComb, b: LinComb, c: LinComb) -> None:
        self.constraints.append((a, b, c))

    def mul(self, a_lc: LinComb, b_lc: LinComb) -> int:
        a_val = _lc_eval(a_lc, self._assignment)
        b_val = _lc_eval(b_lc, self._assignment)
        out = self.alloc(a_val * b_val)
        self.add_constraint(a_lc, b_lc, self.wire_lc(out))
        return out

    def enforce_equal(self, a_lc: LinComb, b_lc: LinComb) -> None:
        self.add_constraint(a_lc, self.const_lc(Fr(1)), b_lc)

    def add(self, *lcs: LinComb) -> LinComb:
        acc: LinComb = {}
        for lc in lcs:
            acc = _lc_add(acc, lc)
        return acc

    def linear_combo(self, terms: List[Tuple[LinComb, Fr]]) -> LinComb:
        acc: LinComb = {}
        for lc, k in terms:
            acc = _lc_add(acc, _lc_scale(lc, Fr(k)))
        return acc

    def value_of(self, lc: LinComb) -> Fr:
        return _lc_eval(lc, self._assignment)

    def finalize(self) -> Tuple[R1CS, List[Fr]]:
        r1cs = R1CS(
            num_wires=self._next_wire,
            num_public=self.num_public,
            constraints=list(self.constraints),
        )
        return r1cs, list(self._assignment)
