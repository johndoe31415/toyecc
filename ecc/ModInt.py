#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2015 Johannes Bauer
#
#	This file is part of joeecc.
#
#	joeecc is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	joeecc is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with joeecc; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#

from .Comparable import Comparable

class ModInt(Comparable):
	def __init__(self, intvalue, modulus):
		assert(isinstance(intvalue, int))
		assert(isinstance(modulus, int))
		self._intvalue = intvalue % modulus
		self._modulus = modulus
		self._rootable = (self._modulus % 4) == 3

	def clone(self):
		return ModInt(self._intvalue, self._modulus)

	@property
	def modulus(self):
		return self._modulus

	def setmodulus(self, modulus):
		assert(isinstance(modulus, int))
		self._modulus = modulus

	def _ioperation(self, value, operation):
		if isinstance(value, int):
			self._intvalue = (operation(self._intvalue, value)) % self._modulus
		elif isinstance(value, ModInt):
			assert(self._modulus == value._modulus)
			self._intvalue = operation(self._intvalue, value._intvalue) % self._modulus
		else:
			raise TypeError("Unsupported type %s." % (str(type(value))))
		return self

	def _eea(a, b):
		assert(isinstance(a, int))
		assert(isinstance(b, int))
		(s, t, u, v) = (1, 0, 0, 1)
		while b != 0:
			(q, r) = (a // b, a % b)
			(uneu, vneu) = (s, t)
			s = u - (q * s)
			t = v - (q * t)
			(a, b) = (b, r)
			(u, v) = (uneu, vneu)
		return (a, u, v)

	def _intdiv(self, a, b):
		if b == 0:
			raise Exception("Division by zero")
		(ggt, u, v) = ModInt._eea(b, self._modulus)
		inverse = (v % self._modulus)
		return (a * inverse)

	def __iadd__(self, value):
		return self._ioperation(value, lambda a, b: a + b)

	def __isub__(self, value):
		return self._ioperation(value, lambda a, b: a - b)

	def __imul__(self, value):
		return self._ioperation(value, lambda a, b: a * b)

	def __ipow__(self, exponent):
		assert(isinstance(exponent, int))
		assert(exponent >= 0)
		self._intvalue = pow(self._intvalue, exponent, self._modulus)
		return self

	def __ifloordiv__(self, value):
		return self._ioperation(value, self._intdiv)

	def __add__(self, value):
		n = self.clone()
		n += value
		return n

	def __radd__(self, value):
		return self + value

	def __sub__(self, value):
		n = self.clone()
		n -= value
		return n

	def __mul__(self, value):
		n = self.clone()
		n *= value
		return n

	def __rmul__(self, value):
		return self * value

	def __floordiv__(self, value):
		n = self.clone()
		n //= value
		return n

	def __pow__(self, value):
		n = self.clone()
		n **= value
		return n

	def __neg__(self):
		n = self.clone()
		n._intvalue = -n._intvalue % self._modulus
		return n

	def __int__(self):
		return self._intvalue

	def sqrt(self):
		assert(self._rootable)
		posroot = self ** ((self._modulus + 1) // 4)
		if (posroot * posroot) == self:
			negroot = -posroot
			return (posroot, negroot)
		else:
			# No square root for this value
			return None

	def inverse(self):
		if self._intvalue == 0:
			raise Exception("Trying to invert zero")
		(ggt, u, v) = ModInt._eea(self._intvalue, self._modulus)
		inverse = (v % self._modulus)
		return inverse

	def cmpkey(self):
		return (self._modulus, self._intvalue)

	def __str__(self):
		return str(self._intvalue)

