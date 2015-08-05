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
import hashlib

from .ModInt import ModInt
from .Random import secure_rand_int_between

ECDSASignature = collections.namedtuple("ECDSASignature", [ "hashalg", "r", "s" ])

class ECKeypair(object):
	def __init__(self, curve, privkey, pubkey):
		assert(isinstance(privkey, int))
		self._curve = curve
		self._privkey = privkey
		self._pubkey = pubkey

	@property
	def curve(self):
		return self._curve

	@property
	def pubkey(self):
		return self._pubkey

	def encrypt(self):
		# Prepare encryption using ECIES
		# Chose a random number
		r = secure_rand_int_between(1, self.curve.n - 1)

		R = r * self.curve.G
		S = r * self._pubkey

		# Return the publicly transmitted R and the symmetric key S
		return { "R": R, "S": S }

	def decrypt(self, R):
		# Transmitted R is given, restore the symmetric key S
		return self._privkey * R

	@staticmethod
	def _bytestoint(b):
		# Use big endian (like OpenSSL does, too)
		return sum([ b[i] * (256 ** (len(b) - 1 - i)) for i in range(len(b)) ])

	def _msgdigest_to_integer(self, message_digest):
		# Convert message digest to integer value
		e = self._bytestoint(message_digest)

		# Truncate hash value if necessary
		msg_digest_bits = 8 * len(message_digest)
		if msg_digest_bits > self.curve.n.bit_length():
			shift = msg_digest_bits - self.curve.n.bit_length()
			e >>= shift

		return e

	def sign_hash(self, message_digest, k = None, digestname = None):
		assert(isinstance(message_digest, bytes))
		assert((k is None) or isinstance(k, int))

		# Convert message digest to integer value
		e = self._msgdigest_to_integer(message_digest)

		# Select a random integer (if None is supplied!)
		if k is None:
			k = secure_rand_int_between(1, self.curve.n - 1)

		# r = (k * G)_x mod n
		Rmodp = k * self.curve.G
		r = int(Rmodp.x) % self.curve.n
		assert(r != 0)

		s = ModInt(e + self._privkey * r, self.curve.n) // k

		return ECDSASignature(r = r, s = int(s), hashalg = digestname)

	def sign_msg(self, message, digestname, k = None):
		assert(isinstance(message, bytes))
		assert(isinstance(digestname, str))
		digest_fnc = hashlib.new(digestname)
		digest_fnc.update(message)
		message_digest = digest_fnc.digest()
		return self.sign_hash(message_digest, k = k, digestname = digestname)

	def verify_hash(self, message_digest, signature):
		assert(isinstance(message_digest, bytes))
		assert(0 < signature.r < self.curve.n)
		assert(0 < signature.s < self.curve.n)

		# Convert message digest to integer value
		e = self._msgdigest_to_integer(message_digest)

		(r, s) = (signature.r, ModInt(signature.s, self.curve.n))
		w = s.inverse()
		u1 = e * w
		u2 = int(r) * w

		pt = (u1 * self.curve.G) + (u2 * self._pubkey)
		x1 = int(pt.x) % self.curve.n
		return x1 == r

	def verify_msg(self, message, signature):
		assert(isinstance(message, bytes))
		digest_fnc = hashlib.new(signature.hashalg)
		digest_fnc.update(message)
		message_digest = digest_fnc.digest()
		return self.verify_hash(message_digest, signature)

	def __str__(self):
		return "Keypair Priv: 0x%x, Pub: %s" % (self._privkey, str(self._pubkey))


