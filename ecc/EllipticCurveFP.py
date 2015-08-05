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

import sys
import hashlib

from .ModInt import ModInt
from .AffineCurvePoint import AffineCurvePoint
from .ECKeypair import ECKeypair
from .Random import secure_rand_int_between

class EllipticCurveFP(object):
	def __init__(self, a, b, p, n, h, Gx, Gy):
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(b, int))		# Curve coefficent B
		assert(isinstance(p, int))		# Modulus
		assert(isinstance(n, int))		# Order
		assert(isinstance(h, int))		# Cofactor
		assert(isinstance(Gx, int))		# Generator Point X
		assert(isinstance(Gy, int))		# Generator Point Y
		self._a = a % p
		self._b = b % p
		self._p = p
		self._n = n
		self._h = h
		if (Gx > 0) and (Gy > 0):
			self._G = AffineCurvePoint(Gx, Gy, self)

		# Check that the curve is not singular
		a = ModInt(a, p)
		b = ModInt(b, p)
		assert(int((4 * (a ** 3)) + (27 * (b ** 2))) != 0)

		# Check that the generator G is on the curve
		if (Gx > 0) and (Gy > 0):
			assert(self._G.oncurve())

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
		# Return a copy so the curve parameters are immutable
		return self._G.clone()

	def genknownkeypair(self, privkey):
		assert(isinstance(privkey, int))
		pubkey = privkey * self._G
		return ECKeypair(self, privkey, pubkey)

	def genkeypair(self):
		privkey = secure_rand_int_between(1, self.curve.n - 1)
		return self.genknownkeypair(privkey)

	def getpointwithx(self, x):
		assert(isinstance(x, int))
		rhs = ((ModInt(x, self._p) ** 3) + (self._a * x) + self._b)
		y = rhs.sqrt()
		if y:
			return (AffineCurvePoint(x, int(y[0]), self), AffineCurvePoint(x, int(y[1]), self))
		else:
			return None

	@staticmethod
	def _bytestoint(b):
		# Convert bytes data to big endian integer
		assert(isinstance(b, bytes))
		return sum([ b[i] * (256 ** (len(b) - 1 - i)) for i in range(len(b)) ])

	def msgdigest_to_integer(self, message_digest):
		# Convert message digest to integer value
		e = self._bytestoint(message_digest)

		# Truncate hash value if necessary
		msg_digest_bits = 8 * len(message_digest)
		if msg_digest_bits > self.n.bit_length():
			shift = msg_digest_bits - self.n.bit_length()
			e >>= shift

		return e

	# Counts points in curve, including point at infinity (therefore yielding n)
	def countpoints(self):
		curpt = self.G
		cnt = 1
		while not curpt.at_infinity:
			cnt += 1
			curpt += self._G
		return cnt

	def getallpoints(self):
		points = [ ]
		curpt = self.G
		while not curpt.at_infinity:
			points.append(curpt.clone())
			curpt += self._G
		return points

	def exploitidenticalnoncesig(self, msg1, sig1, msg2, sig2):
		assert(isinstance(msg1, bytes))
		assert(isinstance(msg2, bytes))
		assert(sig1.r == sig2.r)

		# Hash the messages
		dig1 = hashlib.new(sig1.hashalg)
		dig1.update(msg1)
		dig1 = dig1.digest()
		dig2 = hashlib.new(sig2.hashalg)
		dig2.update(msg2)
		dig2 = dig2.digest()

		# Calculate hashes of messages
		e1 = self.msgdigest_to_integer(dig1)
		e2 = self.msgdigest_to_integer(dig2)

		# Take them modulo n
		e1 = ModInt(e1, self.n)
		e2 = ModInt(e2, self.n)

		(s1, s2) = (ModInt(sig1.s, self.n), ModInt(sig2.s, self.n))
		r = sig1.r

		# Recover (supposedly) random nonce
		nonce = (e1 - e2) // (s1 - s2)

		# Recover private key
		priv = ((nonce * s1) - e1) // r

		return { "nonce": nonce, "privatekey": priv }


	def parsablestr(self):
		return "a=0x%x b=0x%x p=0x%x n=0x%x h=0x%x gx=0x%x gy=0x%x" % (self._a, self._b, self._p, self._n, self._h, self._G.getx().getintvalue(), self._G.gety().getintvalue())

	def __str__(self):
		s = ""
		s += "A: 0x%x\n" % (self._a)
		s += "B: 0x%x\n" % (self._b)
		s += "p: 0x%x\n" % (self._p)
		s += "n: 0x%x\n" % (self._n)
		s += "h: %d\n" % (self._h)
		try:
			s += "G: %s" % (str(self._G))
		except AttributeError:
			s += "Without G"
			pass
		return s

