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

import collections
from .FieldElement import FieldElement
from .AffineCurvePoint import AffineCurvePoint
from .EllipticCurve import EllipticCurve

_ShortWeierstrassCurveDomainParameters = collections.namedtuple("ShortWeierstrassCurveDomainParameters", [ "curvetype", "a", "b", "p", "n", "h", "G" ])

class ShortWeierstrassCurve(EllipticCurve):
	"""Represents an elliptic curve over a finite field F_P that satisfies the
	short Weierstrass equation y^2 = x^3 + ax + b."""

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
		assert(isinstance(Gx, int))		# Generator Point X
		assert(isinstance(Gy, int))		# Generator Point Y
		self._a = FieldElement(a, p)
		self._b = FieldElement(b, p)
		self._p = p
		self._n = n
		self._h = h
		self._name = kwargs.get("name")
		if (Gx > 0) and (Gy > 0):
			self._G = AffineCurvePoint(Gx, Gy, self)

		# Check that the curve is not singular
		assert((4 * (self.a ** 3)) + (27 * (self.b ** 2)) != 0)

		# Check that the generator G is on the curve
		if (Gx > 0) and (Gy > 0):
			assert(self._G.oncurve())

	@property
	def domainparams(self):
		return _ShortWeierstrassCurveDomainParameters(curvetype = self.curvetype, a = self.a, b = self.d, p = self.p, n = self.n, h = self.h, G = self.G)

	@property
	def curvetype(self):
		return "shortweierstrass"

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
		return (P.y ** 2) == (P.x ** 3) + (self.a * P.x) + self.b

	def point_conjugate(self, P):
		return AffineCurvePoint(int(P.x), int(-P.y), self)

	def point_addition(self, P, Q):
		if P.is_neutral:
			# P is at infinity, O + Q = Q
			result = Q
		elif P == -Q:
			# P == -Q, return O (point at infinity)
			result = AffineCurvePoint.neutral(self)
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

	def __str__(self):
		if self.hasname:
			return "ShortWeierstrassCurve<%s>" % (self.name)
		else:
			return "ShortWeierstrassCurve<y^2 = x^3 + 0x%x x + 0x%x>" % (int(self.a), int(self.b))
