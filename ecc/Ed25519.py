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

from .Random import secure_rand_int

import hashlib
import collections

def _hash(data):
	return hashlib.sha512(data).digest()

def _bytes2int(data):
	return sum(value << (8 * index) for (index, value) in enumerate(data))

def _int2bytes(value, length):
	return bytes((value >> (8 * i)) & 0xff for i in range(length))

class CurveParams(object):
	def __init__(self, params):
		self._params = params

	@property
	def B(self):
		return self._params["B"]

	@property
	def Q(self):
		return self._params["Q"]

	@property
	def L(self):
		return self._params["L"]

	@property
	def D(self):
		return self._params["D"]

	@property
	def I(self):
		return self._params["I"]

	@property
	def PB(self):
		return self._params["PB"]

	def update(self, values):
		self._params.update(values)

	def invert(self, value):
		return pow(value, self.Q - 2, self.Q)

Ed25519Params = CurveParams({
	"B":	256,
	"Q":	(2 ** 255) - 19,
	"L":	(2 ** 252) + 27742317777372353535851937790883648493,
	"D":	-4513249062541557337682894930092624173785641285191125241628941591882900924598840740,
	"I":	19681161376707505956807079304988542015446066515923890162744021073123829784752,
})

class Ed25519Point(object):
	def __init__(self, x, y):
		assert(isinstance(x, int))
		assert(isinstance(y, int))
		self._x = x
		self._y = y

	@property
	def x(self):
		return self._x

	@property
	def y(self):
		return self._y

	def __eq__(self, other):
		return (self.x, self.y) == (other.x, other.y)

	def oncurve(self):
		return (-(self.x * self.x) + (self.y * self. y) - 1 - Ed25519Params.D * self.x * self.x * self.y * self.y) % Ed25519Params.Q == 0

	def encode(self):
		enc_value = self.y & ((1 << 255) - 1)
		enc_value = enc_value | ((self.x & 1) << 255)
		return _int2bytes(enc_value, 32)

	@staticmethod
	def _recoverx(y):
		xx = (y * y - 1) * Ed25519Params.invert(Ed25519Params.D * y * y + 1)
		x = pow(xx, (Ed25519Params.Q + 3) // 8, Ed25519Params.Q)
		if ((x * x - xx) % Ed25519Params.Q) != 0:
			x = (x * Ed25519Params.I) % Ed25519Params.Q
		if (x % 2) != 0:
			x = Ed25519Params.Q - x
		return x

	@staticmethod
	def decode(data):
		enc_value = _bytes2int(data)
		y = enc_value & ((1 << 255) - 1)
		x = Ed25519Point._recoverx(y)
		hibit = (enc_value >> 255) & 1
		if (x & 1) != hibit:
			x = Ed25519Params.Q - x
		return Ed25519Point(x, y)

	def __add__(self, other):
		(P, Q) = (self, other)
		x = ((P.x * Q.y + Q.x * P.y) * Ed25519Params.invert(1 + Ed25519Params.D * P.x * Q.x * P.y * Q.y)) % Ed25519Params.Q
		y = ((P.y * Q.y + P.x * Q.x) * Ed25519Params.invert(1 - Ed25519Params.D * P.x * Q.x * P.y * Q.y)) % Ed25519Params.Q
		return Ed25519Point(x, y)

	def __mul__(self, scalar):
		assert(isinstance(scalar, int))
		assert(scalar >= 0)
		result = Ed25519Point(0, 1)
		Q = self
		while scalar > 0:
			if scalar & 1:
				result = result + Q
			Q = Q + Q
			scalar >>= 1
		return result

	def __rmul__(self, scalar):
		return self * scalar

	def __str__(self):
		return "Ed25519Point<0x%x, 0x%x>" % (self.x, self.y)

	def __repr__(self):
		return str(self)

	def verify_msg(self, message, signature):
		h = _bytes2int(_hash(signature.R.encode() + self.encode() + message))
		return (signature.s * Ed25519Params.PB) == signature.R + (h * self)

Ed25519Params.update({
	"PB":	Ed25519Point(x = 15112221349535400772501151409588531511454012693041857206046113283949847762202, y = 46316835694926478169428394003475163141307993866256225615783033603165251855960),
})

class Ed25519Signature(object):
	def __init__(self, R, s):
		self._R = R
		self._s = s

	@property
	def R(self):
		return self._R

	@property
	def s(self):
		return self._s

	def encode(self):
		return self.R.encode() + _int2bytes(self.s, Ed25519Params.B // 8)

	@staticmethod
	def decode(data):
		assert(isinstance(data, bytes))
		assert(len(data) == 64)
		encoded_R = data[:32]
		encoded_s = data[32:]
		R = Ed25519Point.decode(encoded_R)
		s = _bytes2int(encoded_s)
		return Ed25519Signature(R, s)

	def __eq__(self, other):
		return (self.R, self.s) == (other.R, other.s)

	def __str__(self):
		return "Ed25519Signature<R = %s, s = %s>" % (self.R, self.s)

class Ed25519Keypair(object):
	def __init__(self, private):
		assert(isinstance(private, int))
		self._private = private
		self._public = self._calc_public_key()

	@property
	def private(self):
		return self._private

	@property
	def public(self):
		return self._public

	@staticmethod
	def _bitof(data, bitno):
		return (data[bitno // 8] >> (bitno % 8)) & 1

	def _calc_ha(self):
		h = _hash(_int2bytes(self._private, Ed25519Params.B // 8))
		a = (2 ** (Ed25519Params.B - 2)) + sum(Ed25519Keypair._bitof(h, i) << i for i in range(3, Ed25519Params.B - 2))
		return (h, a)

	def _calc_public_key(self):
		(h, a) = self._calc_ha()
		A = a * Ed25519Params.PB
		assert(A.oncurve())
		return A

	@staticmethod
	def loadkeypair(privatekeydata):
		assert(isinstance(privatekeydata, bytes))
		assert(len(privatekeydata) == (Ed25519Params.B // 8))
		private = _bytes2int(privatekeydata)
		return Ed25519Keypair(private)

	@staticmethod
	def genkeypair():
		return Ed25519Keypair(secure_rand_int(Ed25519Params.Q))

	def sign_msg(self, message):
		(h, a) = self._calc_ha()
		r = _bytes2int(_hash(h[32 : 64] + message))
		R = r * Ed25519Params.PB
		s = (r + _bytes2int(_hash(R.encode() + self._public.encode() + message)) * a) % Ed25519Params.L
		sig = Ed25519Signature(R, s)
		return sig

