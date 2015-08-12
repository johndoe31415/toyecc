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
import ecc.MontgomeryCurve

_TwistedEdwardsCurveDomainParameters = collections.namedtuple("TwistedEdwardsCurveDomainParameters", [ "curvetype", "a", "d", "p", "n", "G" ])

class TwistedEdwardsCurve(EllipticCurve):
	"""Represents an elliptic curve over a finite field F_P that satisfies the
	Twisted Edwards equation a x^2 + y^2 = 1 + d x^2 y^2."""

	def __init__(self, a, d, p, n, h, Gx, Gy, **kwargs):
		"""Create an elliptic Twisted Edwards curve given the equation
		coefficients a and d, the curve field's modulus p, the order of the
		curve n and the generator point G's X and Y coordinates in affine
		representation, Gx and Gy."""
		EllipticCurve.__init__(self)
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(d, int))		# Curve coefficent D
		assert(isinstance(p, int))		# Modulus
		assert(isinstance(n, int))		# Order
		assert(isinstance(h, int))		# Cofactor
		assert((Gx is None) or isinstance(Gx, int))		# Generator Point X
		assert((Gy is None) or isinstance(Gy, int))		# Generator Point Y
		self._a = FieldElement(a, p)
		self._d = FieldElement(d, p)
		self._p = p
		self._n = n
		self._h = h
		self._name = kwargs.get("name")
		
		# Check that the curve is not singular
		assert(self.d * (1 - self.d) != 0)
		
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
		return _TwistedEdwardsCurveDomainParameters(curvetype = self.curvetype, a = self.a, d = self.d, p = self.p, n = self.n, G = self.G)

	@property
	def curvetype(self):
		return "twistededwards"

	@property
	def a(self):
		return self._a

	@property
	def d(self):
		return self._d

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

	@property
	def B(self):
		"""Returns the length of the curve's field modulus in bits plus one."""
		return self._p.bit_length() + 1

	@property
	def is_complete(self):
		"""Returns if the twisted Edwards curve is complete. This is the case
		exactly when d is a quadratic non-residue modulo p."""
		return self.d.is_qnr

	def neutral(self):
		return AffineCurvePoint(0, 1, self)

	def is_neutral(self, P):
		return (P.x == 0) and (P.y == 1)

	def oncurve(self, P):
		return (self.a * P.x ** 2) + P.y ** 2 == 1 + self.d * P.x ** 2 * P.y ** 2

	def point_conjugate(self, P):
		return AffineCurvePoint(int(-P.x), int(P.y), self)

	def point_addition(self, P, Q):
		x = (P.x * Q.y + Q.x * P.y) // (1 + self.d * P.x * Q.x * P.y * Q.y)
		y = (P.y * Q.y - self.a * P.x * Q.x) // (1 - self.d * P.x * Q.x * P.y * Q.y)
		return AffineCurvePoint(int(x), int(y), self)

	def to_montgomery(self, b = None):
		"""Converts the twisted Edwards curve domain parameters to Montgomery
		domain parameters. For this conversion, b can be chosen semi-freely.
		If the native b coefficient is a quadratic residue modulo p, then the
		freely chosen b value must also be. If it is a quadratic non-residue,
		then so must be the surrogate b coefficient. If b is omitted, the
		native b value is used. The generator point of the twisted Edwards
		curve is also converted to Montgomery form. For this conversion,
		there's an invariant (one of two possible outcomes). An arbitrary
		bijection is used for this."""
		assert((b is None) or isinstance(b, int))

		# Calculate the native montgomery coefficents a, b first
		a = 2 * (self.a + self.d) // (self.a - self.d)
		native_b = 4 // (self.a - self.d)
		if b is None:
			b = native_b
		else:
			# If a b value was supplied, make sure is is either a QR or QNR mod
			# p, depending on what the native b value was
			b = FieldElement(b, self.p)
			if native_b.is_qr != b.is_qr:
				raise Exception("The b coefficient of the resulting curve must be a quadratic %s modulo p, %s is not." % ([ "non-residue", "residue" ][native_b.is_qr], str(b)))

		# Generate the raw curve without a generator yet
		raw_curve = ecc.MontgomeryCurve.MontgomeryCurve(
			a = int(a),
			b = int(b),
			p = self.p,
			n = self.n,
			h = self.h,
			Gx = None,
			Gy = None,
		)

		# Then convert the original generator point using the raw curve to
		# yield a birationally equivalent generator point
		G_m = self.G.convert(raw_curve)

		# And create the curve again, setting this generator
		montgomery_curve = ecc.MontgomeryCurve.MontgomeryCurve(
			a = int(a),
			b = int(b),
			p = self.p,
			n = self.n,
			h = self.h,
			Gx = int(G_m.x),
			Gy = int(G_m.y),
		)

		return montgomery_curve

	def __str__(self):
		if self.hasname:
			return "TwistedEdwardsCurve<%s>" % (self.name)
		else:
			return "TwistedEdwardsCurve<0x%x x^2 + y^2 = 1 + 0x%x x^2 y^2 mod 0x%x>" % (int(self.a), int(self.d), int(self.p))

