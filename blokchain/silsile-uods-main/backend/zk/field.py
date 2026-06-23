from __future__ import annotations

from py_ecc.bn128 import curve_order

FIELD_MODULUS = curve_order


class Fr:
    __slots__ = ("v",)

    def __init__(self, value):
        if isinstance(value, Fr):
            self.v = value.v
        else:
            self.v = int(value) % FIELD_MODULUS

    @staticmethod
    def zero() -> "Fr":
        return Fr(0)

    @staticmethod
    def one() -> "Fr":
        return Fr(1)

    def __add__(self, other) -> "Fr":
        return Fr(self.v + Fr(other).v)

    def __radd__(self, other) -> "Fr":
        return Fr(Fr(other).v + self.v)

    def __sub__(self, other) -> "Fr":
        return Fr(self.v - Fr(other).v)

    def __rsub__(self, other) -> "Fr":
        return Fr(Fr(other).v - self.v)

    def __mul__(self, other) -> "Fr":
        return Fr(self.v * Fr(other).v)

    def __rmul__(self, other) -> "Fr":
        return Fr(Fr(other).v * self.v)

    def __neg__(self) -> "Fr":
        return Fr(-self.v)

    def inv(self) -> "Fr":
        if self.v == 0:
            raise ZeroDivisionError("Fr(0) tersi yok")
        return Fr(pow(self.v, FIELD_MODULUS - 2, FIELD_MODULUS))

    def __truediv__(self, other) -> "Fr":
        return self * Fr(other).inv()

    def __pow__(self, exponent: int) -> "Fr":
        return Fr(pow(self.v, int(exponent) % (FIELD_MODULUS - 1), FIELD_MODULUS))

    def __eq__(self, other) -> bool:
        return self.v == Fr(other).v

    def __hash__(self) -> int:
        return hash(self.v)

    def __int__(self) -> int:
        return self.v

    def __repr__(self) -> str:
        return f"Fr({self.v})"


def to_fr_list(values) -> list:
    return [Fr(v) for v in values]
