from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .field import FIELD_MODULUS, Fr
from .r1cs import R1CS


def _eval_poly(coeffs: List[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % FIELD_MODULUS
    return acc


def _poly_add(a: List[int], b: List[int]) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(len(a)):
        out[i] = a[i]
    for i in range(len(b)):
        out[i] = (out[i] + b[i]) % FIELD_MODULUS
    return out


def _poly_mul(a: List[int], b: List[int]) -> List[int]:
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * bj) % FIELD_MODULUS
    return out


def _poly_scale(a: List[int], k: int) -> List[int]:
    return [(c * k) % FIELD_MODULUS for c in a]


def _poly_sub(a: List[int], b: List[int]) -> List[int]:
    return _poly_add(a, _poly_scale(b, FIELD_MODULUS - 1))


def _inv(x: int) -> int:
    return pow(x % FIELD_MODULUS, FIELD_MODULUS - 2, FIELD_MODULUS)


def lagrange_interpolate(xs: List[int], ys: List[int]) -> List[int]:
    n = len(xs)
    result = [0]
    for i in range(n):
        num = [1]
        denom = 1
        for j in range(n):
            if j == i:
                continue
            num = _poly_mul(num, [(-xs[j]) % FIELD_MODULUS, 1])
            denom = (denom * ((xs[i] - xs[j]) % FIELD_MODULUS)) % FIELD_MODULUS
        term = _poly_scale(num, (ys[i] * _inv(denom)) % FIELD_MODULUS)
        result = _poly_add(result, term)
    return result


_BASIS_CACHE = {}


def _synthetic_div_by_root(coeffs: List[int], root: int) -> List[int]:
    out = [0] * (len(coeffs) - 1)
    acc = 0
    for k in range(len(coeffs) - 1, 0, -1):
        acc = (coeffs[k] + acc * root) % FIELD_MODULUS
        out[k - 1] = acc
    return out


def lagrange_basis(domain: List[int]) -> List[List[int]]:
    key = (domain[0], len(domain))
    cached = _BASIS_CACHE.get(key)
    if cached is not None:
        return cached
    z = _vanishing_poly(domain)
    basis: List[List[int]] = []
    for i, xi in enumerate(domain):
        num = _synthetic_div_by_root(z, xi)
        denom = 1
        for j, xj in enumerate(domain):
            if j != i:
                denom = denom * ((xi - xj) % FIELD_MODULUS) % FIELD_MODULUS
        inv = _inv(denom)
        basis.append([(c * inv) % FIELD_MODULUS for c in num])
    _BASIS_CACHE[key] = basis
    return basis


def interpolate_with_basis(domain: List[int], values: List[int]) -> List[int]:
    basis = lagrange_basis(domain)
    m = len(domain)
    result = [0] * m
    for i in range(m):
        yi = values[i] % FIELD_MODULUS
        if yi == 0:
            continue
        bi = basis[i]
        for d in range(len(bi)):
            result[d] = (result[d] + yi * bi[d]) % FIELD_MODULUS
    return result


def _vanishing_poly(roots: List[int]) -> List[int]:
    poly = [1]
    for r in roots:
        poly = _poly_mul(poly, [(-r) % FIELD_MODULUS, 1])
    return poly


def _poly_divmod(num: List[int], den: List[int]):
    num = list(num)
    while len(num) > 1 and num[-1] == 0:
        num.pop()
    den = list(den)
    while len(den) > 1 and den[-1] == 0:
        den.pop()
    if den == [0]:
        raise ZeroDivisionError("sifir polinoma bolme")
    quotient = [0] * (max(len(num) - len(den) + 1, 1))
    inv_lead = _inv(den[-1])
    work = list(num)
    for i in range(len(num) - len(den), -1, -1):
        coeff = (work[i + len(den) - 1] * inv_lead) % FIELD_MODULUS
        quotient[i] = coeff
        for j in range(len(den)):
            work[i + j] = (work[i + j] - coeff * den[j]) % FIELD_MODULUS
    remainder = work[: len(den) - 1]
    while len(remainder) > 1 and remainder[-1] == 0:
        remainder.pop()
    return quotient, remainder


@dataclass
class QAP:
    a_polys: List[List[int]]
    b_polys: List[List[int]]
    c_polys: List[List[int]]
    z_poly: List[int]
    domain: List[int]
    num_wires: int
    num_public: int

    @property
    def degree(self) -> int:
        return len(self.domain)


def r1cs_to_qap(r1cs: R1CS) -> QAP:
    m = len(r1cs.constraints)
    domain = [i + 1 for i in range(m)]
    num_wires = r1cs.num_wires

    a_evals = [[0] * m for _ in range(num_wires)]
    b_evals = [[0] * m for _ in range(num_wires)]
    c_evals = [[0] * m for _ in range(num_wires)]

    for k, (a_lc, b_lc, c_lc) in enumerate(r1cs.constraints):
        for wire, coeff in a_lc.items():
            a_evals[wire][k] = int(coeff)
        for wire, coeff in b_lc.items():
            b_evals[wire][k] = int(coeff)
        for wire, coeff in c_lc.items():
            c_evals[wire][k] = int(coeff)

    a_polys = [lagrange_interpolate(domain, a_evals[w]) for w in range(num_wires)]
    b_polys = [lagrange_interpolate(domain, b_evals[w]) for w in range(num_wires)]
    c_polys = [lagrange_interpolate(domain, c_evals[w]) for w in range(num_wires)]
    z_poly = _vanishing_poly(domain)

    return QAP(
        a_polys=a_polys,
        b_polys=b_polys,
        c_polys=c_polys,
        z_poly=z_poly,
        domain=domain,
        num_wires=num_wires,
        num_public=r1cs.num_public,
    )


def compute_h_poly(qap: QAP, witness: List[Fr]):
    w = [int(x) for x in witness]
    a_sum = [0]
    b_sum = [0]
    c_sum = [0]
    for i in range(qap.num_wires):
        if w[i] == 0:
            continue
        a_sum = _poly_add(a_sum, _poly_scale(qap.a_polys[i], w[i]))
        b_sum = _poly_add(b_sum, _poly_scale(qap.b_polys[i], w[i]))
        c_sum = _poly_add(c_sum, _poly_scale(qap.c_polys[i], w[i]))
    ab = _poly_mul(a_sum, b_sum)
    t = _poly_sub(ab, c_sum)
    h, rem = _poly_divmod(t, qap.z_poly)
    rem_clean = [r for r in rem if r != 0]
    if rem_clean:
        raise ValueError("QAP bolme kalanli: taniklik R1CS'i saglamiyor")
    return h
