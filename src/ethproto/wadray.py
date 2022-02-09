import os
from functools import partial
from contextlib import contextmanager
from decimal import Decimal

__author__ = "Guillermo M. Narvaja"
__copyright__ = "Guillermo M. Narvaja"
__license__ = "MIT"

WAD = 10**18
RAY = 10**27

int_float_classes = {}


def make_integer_float_pyint(decimals, name=None):
    global int_float_classes

    class Ret(int):
        DEFAULT_EQ_PRECISION = min(decimals, 4)
        ONE = 10**decimals
        DECIMALS = decimals

        def __mul__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(int(self) * int(other) // self.ONE)

        def __floordiv__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(int(self) * self.ONE // other)

        def __add__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(int(self) + int(other))

        def __sub__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(int(self) - int(other))

        def __neg__(self):
            return self.__class__(-int(self))

        def __str__(self):
            return str(Decimal(self) / Decimal(self.ONE))

        def __repr__(self):
            return str(Decimal(self) / Decimal(self.ONE))

        # def to_ray(self):
        #    return Ray(int(self) * 10**9)

        def equal(self, other, decimals=None):
            if decimals is None:
                decimals = self.DEFAULT_EQ_PRECISION
            return abs(other - self) < (10**(self.DECIMALS-decimals))

        def assert_equal(self, other, decimals=None):
            if decimals is None:
                decimals = self.DEFAULT_EQ_PRECISION
            diff = abs(other - self)
            max_diff = (10**(self.DECIMALS-decimals))
            assert diff < max_diff, f"{self} != {other} diff {self - other}"

        @classmethod
        def from_value(cls, value):
            if type(value) == str:
                value = Decimal(value)
            elif type(value) == cls:
                return value
            return cls(int(value * cls.ONE))

        def _to(self, other_cls):
            if other_cls.DECIMALS > self.DECIMALS:
                return other_cls(int(self) * 10**(other_cls.DECIMALS - self.DECIMALS))
            else:
                return other_cls(int(self) // 10**(self.DECIMALS - other_cls.DECIMALS))

        def __getattr__(self, attr_value):
            if attr_value.startswith("to_"):
                class_lower = attr_value[3:]
                if class_lower in int_float_classes:
                    other_cls = int_float_classes[class_lower]
                    return partial(self._to, other_cls)
            return super().__getattr__(attr_value)

        def to_float(self):
            return int(self) / self.ONE

        def to_decimal(self):
            return Decimal(int(self)) / Decimal(self.ONE)

        def round(self, decimals):
            iself = int(self)
            iself = iself - iself % 10 ** (self.DECIMALS - decimals)
            return self.__class__(iself)

    if name is None:
        Ret.__name__ = "IntDec%d" % decimals
        Ret.__qualname__ = "IntDec%d" % decimals
    else:
        Ret.__name__ = name
        Ret.__qualname__ = name

    if Ret.__name__.lower() not in int_float_classes:
        int_float_classes[Ret.__name__.lower()] = Ret
    return Ret


def make_integer_float_gmpy(decimals, name=None):
    global int_float_classes
    from gmpy2 import mpz

    class Ret:
        DEFAULT_EQ_PRECISION = min(decimals, 4)
        ONE = mpz(10**decimals)
        DECIMALS = decimals

        def __init__(self, value):
            self._value = mpz(value)

        def __mul__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(self._value * other._value // self.ONE)

        def __floordiv__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(self._value * self.ONE // other._value)

        def __add__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(self._value + other._value)

        def __sub__(self, other):
            assert isinstance(other, self.__class__)
            return self.__class__(self._value - other._value)

        def __neg__(self):
            return self.__class__(-self._value)

        def __str__(self):
            return str(Decimal(int(self._value)) / Decimal(int(self.ONE)))

        def __repr__(self):
            return str(Decimal(int(self._value)) / Decimal(int(self.ONE)))

        # def to_ray(self):
        #    return Ray(int(self) * 10**9)

        def equal(self, other, decimals=None):
            if decimals is None:
                decimals = self.DEFAULT_EQ_PRECISION
            return abs(other._value - self._value) < (mpz(10)**(self.DECIMALS-decimals))

        def assert_equal(self, other, decimals=None):
            if decimals is None:
                decimals = self.DEFAULT_EQ_PRECISION
            diff = abs(other._value - self._value)
            max_diff = (10**(self.DECIMALS-decimals))
            assert diff < max_diff, f"{self} != {other} diff {self._value - other._value}"

        @classmethod
        def from_value(cls, value):
            if type(value) == str:
                value = Decimal(value)
            elif type(value) == cls:
                return value
            return cls(value * int(cls.ONE))

        def __eq__(self, other):
            if isinstance(other, int):
                return self._value == other
            elif isinstance(other, float):
                return self._value == other
            return self._value == other._value

        def __lt__(self, other):
            if other is int(0):
                return self._value < other
            return self._value < other._value

        def __gt__(self, other):
            if other is int(0):
                return self._value > other
            return self._value > other._value

        def __le__(self, other):
            if other is int(0):
                return self._value <= other
            return self._value <= other._value

        def __ge__(self, other):
            if other is int(0):
                return self._value >= other
            return self._value >= other._value

        def __int__(self):
            return int(self._value)

        def _to(self, other_cls):
            if other_cls.DECIMALS > self.DECIMALS:
                return other_cls(self._value * mpz(10)**(other_cls.DECIMALS - self.DECIMALS))
            else:
                return other_cls(self._value // mpz(10)**(self.DECIMALS - other_cls.DECIMALS))

        def __getattr__(self, attr_value):
            if attr_value.startswith("to_"):
                class_lower = attr_value[3:]
                if class_lower in int_float_classes:
                    other_cls = int_float_classes[class_lower]
                    return partial(self._to, other_cls)
            return super().__getattr__(attr_value)

        def to_float(self):
            return float(self._value / self.ONE)

        def to_decimal(self):
            return Decimal(self._value) / Decimal(int(self.ONE))

        def round(self, decimals):
            iself = self._value
            iself = iself - iself % 10 ** (self.DECIMALS - decimals)
            return self.__class__(iself)

    if name is None:
        Ret.__name__ = "IntDec%d" % decimals
        Ret.__qualname__ = "IntDec%d" % decimals
    else:
        Ret.__name__ = name
        Ret.__qualname__ = name

    if Ret.__name__.lower() not in int_float_classes:
        int_float_classes[Ret.__name__.lower()] = Ret
    return Ret


if os.environ.get("WADRAY_USE_GMPY2", None) == "T":
    make_integer_float = make_integer_float_gmpy
else:
    make_integer_float = make_integer_float_pyint

Wad = make_integer_float(18, "Wad")
Ray = make_integer_float(27, "Ray")


_R = Ray.from_value
_W = Wad.from_value


@contextmanager
def set_precision(cls, precision):
    old_precision = cls.DEFAULT_EQ_PRECISION
    cls.DEFAULT_EQ_PRECISION = precision
    try:
        yield
    finally:
        cls.DEFAULT_EQ_PRECISION = old_precision
