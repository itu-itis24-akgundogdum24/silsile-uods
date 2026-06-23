from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Tuple

from py_ecc.optimized_bn128 import (
    G1,
    G2,
    Z1,
    Z2,
    add,
    curve_order,
    multiply,
    neg,
    pairing,
    normalize,
)
from py_ecc.optimized_bn128 import FQ12

def _final_exp_eq(a, b) -> bool:
    return a == b

from .field import FIELD_MODULUS
from .qap import (
    QAP,
    _inv,
    _poly_add,
    _poly_divmod,
    _poly_mul,
    _poly_scale,
    _poly_sub,
    _vanishing_poly,
    r1cs_to_qap,
)
from .r1cs import R1CS

P = curve_order


def _rand_scalar() -> int:
    return random.randrange(1, P)


def _g1_mul(s: int):
    s = s % P
    if s == 0:
        return Z1
    return multiply(G1, s)


def _g2_mul(s: int):
    s = s % P
    if s == 0:
        return Z2
    return multiply(G2, s)


def _g1_add(a, b):
    return add(a, b)


def _lk_at_tau(domain: List[int], tau: int) -> List[int]:
    diffs = [(tau - x) % P for x in domain]
    full = 1
    for d in diffs:
        full = full * d % P
    out = []
    m = len(domain)
    for k in range(m):
        num = full * _inv(diffs[k]) % P
        den = 1
        xk = domain[k]
        for j in range(m):
            if j != k:
                den = den * ((xk - domain[j]) % P) % P
        out.append(num * _inv(den) % P)
    return out


def _poly_at(coeffs: List[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % P
    return acc


@dataclass
class ProvingKey:
    alpha_g1: tuple
    beta_g1: tuple
    delta_g1: tuple
    beta_g2: tuple
    delta_g2: tuple
    a_query: List[tuple]
    b_query_g1: List[tuple]
    b_query_g2: List[tuple]
    k_query: List[tuple]
    h_query: List[tuple]
    num_wires: int
    num_public: int
    degree: int


@dataclass
class VerifyingKey:
    alpha_g1: tuple
    beta_g2: tuple
    gamma_g2: tuple
    delta_g2: tuple
    ic: List[tuple]
    num_public: int


@dataclass
class Proof:
    a: tuple
    b: tuple
    c: tuple
    public_inputs: List[int]


def setup(r1cs: R1CS) -> Tuple[ProvingKey, VerifyingKey]:
    m = len(r1cs.constraints)
    n = r1cs.num_wires
    pub = r1cs.num_public
    domain = [i + 1 for i in range(m)]
    z_poly = _vanishing_poly(domain)

    tau = _rand_scalar()
    alpha = _rand_scalar()
    beta = _rand_scalar()
    gamma = _rand_scalar()
    delta = _rand_scalar()
    gamma_inv = _inv(gamma)
    delta_inv = _inv(delta)

    lk = _lk_at_tau(domain, tau)

    a_tau = [0] * n
    b_tau = [0] * n
    c_tau = [0] * n
    a_evals = [[0] * m for _ in range(n)]
    b_evals = [[0] * m for _ in range(n)]
    c_evals = [[0] * m for _ in range(n)]
    for k, (a_lc, b_lc, c_lc) in enumerate(r1cs.constraints):
        for wire, coeff in a_lc.items():
            a_evals[wire][k] = int(coeff)
        for wire, coeff in b_lc.items():
            b_evals[wire][k] = int(coeff)
        for wire, coeff in c_lc.items():
            c_evals[wire][k] = int(coeff)
    for w in range(n):
        a_tau[w] = sum(a_evals[w][k] * lk[k] for k in range(m)) % P
        b_tau[w] = sum(b_evals[w][k] * lk[k] for k in range(m)) % P
        c_tau[w] = sum(c_evals[w][k] * lk[k] for k in range(m)) % P

    z_tau = _poly_at(z_poly, tau)

    a_query = [_g1_mul(a_tau[w]) for w in range(n)]
    b_query_g1 = [_g1_mul(b_tau[w]) for w in range(n)]
    b_query_g2 = [_g2_mul(b_tau[w]) for w in range(n)]

    k_query: List[tuple] = []
    for w in range(n):
        val = (beta * a_tau[w] + alpha * b_tau[w] + c_tau[w]) % P
        if w < pub:
            k_query.append(Z1)
        else:
            k_query.append(_g1_mul(val * delta_inv % P))

    ic: List[tuple] = []
    for w in range(pub):
        val = (beta * a_tau[w] + alpha * b_tau[w] + c_tau[w]) % P
        ic.append(_g1_mul(val * gamma_inv % P))

    deg_h = max(m - 1, 1)
    h_query: List[tuple] = []
    tau_pow = 1
    for i in range(deg_h):
        h_query.append(_g1_mul(tau_pow * z_tau % P * delta_inv % P))
        tau_pow = tau_pow * tau % P

    pk = ProvingKey(
        alpha_g1=_g1_mul(alpha),
        beta_g1=_g1_mul(beta),
        delta_g1=_g1_mul(delta),
        beta_g2=_g2_mul(beta),
        delta_g2=_g2_mul(delta),
        a_query=a_query,
        b_query_g1=b_query_g1,
        b_query_g2=b_query_g2,
        k_query=k_query,
        h_query=h_query,
        num_wires=n,
        num_public=pub,
        degree=m,
    )
    vk = VerifyingKey(
        alpha_g1=_g1_mul(alpha),
        beta_g2=_g2_mul(beta),
        gamma_g2=_g2_mul(gamma),
        delta_g2=_g2_mul(delta),
        ic=ic,
        num_public=pub,
    )
    return pk, vk


def _interpolate(domain: List[int], values: List[int]) -> List[int]:
    from .qap import interpolate_with_basis

    return interpolate_with_basis(domain, values)


def _compute_h_coeffs(r1cs: R1CS, witness: List[int]) -> List[int]:
    m = len(r1cs.constraints)
    domain = [i + 1 for i in range(m)]
    z_poly = _vanishing_poly(domain)

    a_vals = [0] * m
    b_vals = [0] * m
    c_vals = [0] * m
    for k, (a_lc, b_lc, c_lc) in enumerate(r1cs.constraints):
        av = 0
        for wire, coeff in a_lc.items():
            av = (av + int(coeff) * witness[wire]) % P
        bv = 0
        for wire, coeff in b_lc.items():
            bv = (bv + int(coeff) * witness[wire]) % P
        cv = 0
        for wire, coeff in c_lc.items():
            cv = (cv + int(coeff) * witness[wire]) % P
        a_vals[k] = av
        b_vals[k] = bv
        c_vals[k] = cv

    a_poly = _interpolate(domain, a_vals)
    b_poly = _interpolate(domain, b_vals)
    c_poly = _interpolate(domain, c_vals)
    ab = _poly_mul(a_poly, b_poly)
    t = _poly_sub(ab, c_poly)
    h, rem = _poly_divmod(t, z_poly)
    if any(r % P != 0 for r in rem):
        raise ValueError("Taniklik QAP'i saglamiyor (H bolumu kalanli)")
    return h


def prove(pk: ProvingKey, r1cs: R1CS, witness: List) -> Proof:
    w = [int(x) % P for x in witness]
    n = pk.num_wires

    r = _rand_scalar()
    s = _rand_scalar()

    a_g1 = pk.alpha_g1
    for i in range(n):
        if w[i] != 0:
            a_g1 = _g1_add(a_g1, multiply(pk.a_query[i], w[i]))
    a_g1 = _g1_add(a_g1, multiply(pk.delta_g1, r))

    b_g2 = pk.beta_g2
    for i in range(n):
        if w[i] != 0:
            b_g2 = add(b_g2, multiply(pk.b_query_g2[i], w[i]))
    b_g2 = add(b_g2, multiply(pk.delta_g2, s))

    b_g1 = pk.beta_g1
    for i in range(n):
        if w[i] != 0:
            b_g1 = _g1_add(b_g1, multiply(pk.b_query_g1[i], w[i]))
    b_g1 = _g1_add(b_g1, multiply(pk.delta_g1, s))

    h = _compute_h_coeffs(r1cs, w)
    h_g1 = Z1
    for i, coeff in enumerate(h):
        if coeff % P != 0 and i < len(pk.h_query):
            h_g1 = _g1_add(h_g1, multiply(pk.h_query[i], coeff % P))

    c_g1 = Z1
    for i in range(pk.num_public, n):
        if w[i] != 0:
            c_g1 = _g1_add(c_g1, multiply(pk.k_query[i], w[i]))
    c_g1 = _g1_add(c_g1, h_g1)
    c_g1 = _g1_add(c_g1, multiply(a_g1, s))
    c_g1 = _g1_add(c_g1, multiply(b_g1, r))
    c_g1 = _g1_add(c_g1, neg(multiply(pk.delta_g1, (r * s) % P)))

    public_inputs = [w[i] for i in range(1, pk.num_public)]
    return Proof(a=a_g1, b=b_g2, c=c_g1, public_inputs=public_inputs)


def _g1_xy(point) -> Tuple[int, int]:
    if point == Z1:
        return (0, 0)
    x, y = normalize(point)
    return (int(x), int(y))


def _g2_xy(point):
    if point == Z2:
        return ((0, 0), (0, 0))
    x, y = normalize(point)
    xc = x.coeffs
    yc = y.coeffs
    return ((int(xc[1]), int(xc[0])), (int(yc[1]), int(yc[0])))


def serialize_proof_for_solidity(proof: Proof) -> dict:
    ax, ay = _g1_xy(proof.a)
    (bx1, bx0), (by1, by0) = _g2_xy(proof.b)
    cx, cy = _g1_xy(proof.c)
    return {
        "a": [ax, ay],
        "b": [[bx1, bx0], [by1, by0]],
        "c": [cx, cy],
        "publicInputs": [int(x) % P for x in proof.public_inputs],
    }


def serialize_vk_for_solidity(vk: VerifyingKey) -> dict:
    ax, ay = _g1_xy(vk.alpha_g1)
    (bx1, bx0), (by1, by0) = _g2_xy(vk.beta_g2)
    (gx1, gx0), (gy1, gy0) = _g2_xy(vk.gamma_g2)
    (dx1, dx0), (dy1, dy0) = _g2_xy(vk.delta_g2)
    ic = [list(_g1_xy(p)) for p in vk.ic]
    return {
        "alpha": [ax, ay],
        "beta": [[bx1, bx0], [by1, by0]],
        "gamma": [[gx1, gx0], [gy1, gy0]],
        "delta": [[dx1, dx0], [dy1, dy0]],
        "ic": ic,
        "numPublic": vk.num_public,
    }


def serialize_proof_to_dict(proof: Proof) -> dict:
    ax, ay = _g1_xy(proof.a)
    (bx1, bx0), (by1, by0) = _g2_xy(proof.b)
    cx, cy = _g1_xy(proof.c)
    return {
        "a": [str(ax), str(ay)],
        "b": [[str(bx1), str(bx0)], [str(by1), str(by0)]],
        "c": [str(cx), str(cy)],
        "public_inputs": [str(int(x) % P) for x in proof.public_inputs],
    }


def serialize_vk_to_dict(vk: VerifyingKey) -> dict:
    sol = serialize_vk_for_solidity(vk)
    return {
        "alpha": [str(v) for v in sol["alpha"]],
        "beta": [[str(v) for v in pair] for pair in sol["beta"]],
        "gamma": [[str(v) for v in pair] for pair in sol["gamma"]],
        "delta": [[str(v) for v in pair] for pair in sol["delta"]],
        "ic": [[str(v) for v in pt] for pt in sol["ic"]],
        "num_public": vk.num_public,
    }


def verify(vk: VerifyingKey, proof: Proof) -> bool:
    if len(proof.public_inputs) != vk.num_public - 1:
        raise ValueError("public input sayisi VK ile uyusmuyor")

    vk_x = vk.ic[0]
    for i, val in enumerate(proof.public_inputs):
        vk_x = add(vk_x, multiply(vk.ic[i + 1], val % P))

    lhs = pairing(proof.b, proof.a)
    rhs = (
        pairing(vk.beta_g2, vk.alpha_g1)
        * pairing(vk.gamma_g2, vk_x)
        * pairing(vk.delta_g2, proof.c)
    )
    return lhs == rhs
