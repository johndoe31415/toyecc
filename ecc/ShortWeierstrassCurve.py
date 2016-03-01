#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2016 Johannes Bauer
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

import collections
from .FieldElement import FieldElement
from .AffineCurvePoint import AffineCurvePoint
from .EllipticCurve import EllipticCurve

_ShortWeierstrassCurveDomainParameters = collections.namedtuple("ShortWeierstrassCurveDomainParameters", [ "curvetype", "a", "b", "p", "n", "h", "G" ])

class ShortWeierstrassCurve(EllipticCurve):
	"""Represents an elliptic curve over a finite field F_P that satisfies the
	short Weierstrass equation y^2 = x^3 + ax + b."""
	pretty_name = "Short Weierstrass"

	def __init__(self, a, b, p, n, h, Gx, Gy, **kwargs):
		"""Create an elliptic curve given the equation coefficients a and b,
		the curve modulus p, the order of the curve n, the cofactor of the
		curve h and the generator point G's X and Y coordinates in affine
		representation, Gx and Gy."""
		EllipticCurve.__init__(self)
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(b, int))		# Curve coefficent B
		assert(isinstance(p, int))		# Modulus
		assert(isinstance(n, int))		# Order
		assert(isinstance(h, int))		# Cofactor
		assert((Gx is None) or isinstance(Gx, int))		# Generator Point X
		assert((Gy is None) or isinstance(Gy, int))		# Generator Point Y
		self._a = FieldElement(a, p)
		self._b = FieldElement(b, p)
		self._p = p
		self._n = n
		self._h = h
		self._name = kwargs.get("name")

		# Check that the curve is not singular
		assert((4 * (self.a ** 3)) + (27 * (self.b ** 2)) != 0)

		if (Gx is not None) or (Gy is not None):
			# Check that the generator G is on the curve
			self._G = AffineCurvePoint(Gx, Gy, self)
			assert(self._G.oncurve())

			# Check that the generator G is of curve order
			assert((self.n * self.G).is_neutral)
		else:
			self._G = None

	@property
	def domainparams(self):
		return _ShortWeierstrassCurveDomainParameters(curvetype = self.curvetype, a = self.a, b = self.b, p = self.p, n = self.n, h = self.h, G = self.G)

	@property
	def curvetype(self):
		return "shortweierstrass"

	@property
	def is_koblitz(self):
		"""Returns whether the curve allows for efficient computation of a map
		\phi in the field (i.e. that the curve is commonly known as a 'Koblitz
		Curve'). This corresponds to examples 3 and 4 of the paper "Faster
		Point Multiplication on Elliptic Curves with Efficient Endomorphisms"
		by Gallant, Lambert and Vanstone."""
		return ((self.b == 0) and ((self.p % 4) == 1)) or ((self.a == 0) and ((self.p % 3) == 1))

	@property
	def security_bit_estimate(self):
		"""Returns the bit security estimate of the curve. Subtracts four bits
		security margin for Koblitz curves."""
		security_bits = self.n.bit_length() // 2
		if self.is_koblitz:
			security_bits -= 4
		return security_bits

	@property
	def prettyname(self):
		if not self.is_koblitz:
			return self.pretty_name
		else:
			return self.pretty_name + " (Koblitz)"

	@property
	def a(self):
		return self._a

	@property
	def b(self):
		return self._b

	@property
	def p(self):
		return self._p

	@property
	def n(self):
		return self._n

	@property
	def h(self):
		return self._h

	@property
	def G(self):
		return self._G

	def getpointwithx(self, x):
		assert(isinstance(x, int))
		yy = ((FieldElement(x, self._p) ** 3) + (self._a * x) + self._b)
		y = yy.sqrt()
		if y:
			return (AffineCurvePoint(x, int(y[0]), self), AffineCurvePoint(x, int(y[1]), self))
		else:
			return None

	def oncurve(self, P):
		return P.is_neutral or ((P.y ** 2) == (P.x ** 3) + (self.a * P.x) + self.b)

	def point_conjugate(self, P):
		return AffineCurvePoint(int(P.x), int(-P.y), self)

	def point_addition(self, P, Q):
		if P.is_neutral:
			# P is at infinity, O + Q = Q
			result = Q
		elif Q.is_neutral:
			# Q is at infinity, P + O = P
			result = P
		elif P == -Q:
			# P == -Q, return O (point at infinity)
			result = self.neutral()
		elif P == Q:
			# P == Q, point doubling
			s = ((3 * P.x ** 2) + self.a) // (2 * P.y)
			newx = s * s - (2 * P.x)
			newy = s * (P.x - newx) - P.y
			result = AffineCurvePoint(int(newx), int(newy), self)
		else:
			# P != Q, point addition
			s = (P.y - Q.y) // (P.x - Q.x)
			newx = (s ** 2) - P.x - Q.x
			newy = s * (P.x - newx) - P.y
			result = AffineCurvePoint(int(newx), int(newy), self)
		return result

	def compress(self, P):
		return (int(P.x), int(P.y) % 2)

	def uncompress(self, compressed):
		(x, ybit) = compressed
		x = FieldElement(x, self.p)
		alpha = (x ** 3) + (self.a * x) + self.b
		(beta1, beta2) = alpha.sqrt()
		if (int(beta1) % 2) == ybit:
			y = beta1
		else:
			y = beta2
		return AffineCurvePoint(int(x), int(y), self)

	def enumerate_points(self):
		yield self.neutral()
		for x in range(self.p):
			points = self.getpointwithx(x)
			if points is not None:
				yield points[0]
				yield points[1]

	def __str__(self):
		if self.hasname:
			return "ShortWeierstrassCurve<%s>" % (self.name)
		else:
			return "ShortWeierstrassCurve<y^2 = x^3 + 0x%x x + 0x%x mod 0x%x>" % (int(self.a), int(self.b), int(self.p))
