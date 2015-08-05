#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2011 Johannes Bauer
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

import random
import hashlib

from ModInt import ModInt

class ECKeypair():
	def __init__(self, curve, privkey, pubkey):
		assert(isinstance(privkey, int))
		self._curve = curve
		self._privkey = privkey
		self._pubkey = pubkey
	
	def _bytestoint(b):
		# Use big endian (like OpenSSL does, too)
		return sum([ b[i] * (256 ** (len(b) - 1 - i)) for i in range(len(b)) ])

	def encrypt(self):
		# Prepare encryption using IEC
		# Chose a random number
		r = random.randint(0, 100000)

		R = r * self._curve.getG()
		S = r * self._pubkey

		# Return the publicly transmitted R and the symmetric key S
		return { "R": R, "S": S }

	def decrypt(self, R):
		# Transmitted R is given, restore the symmetric key S
		return self._privkey * R

	def sign(self, message, k = None):
		assert((k is None) or isinstance(k, int))

		# Calculate hash of message
		e = ECKeypair._bytestoint(hashlib.sha1(message.encode("utf-8")).digest())

		# Select a random integer (if None is supplied!)
		if k is None:
			k = random.randint(0, 1000000)

		# r = (k * G)_x mod n
		Rmodp = k * self._curve.getG()	
		r = Rmodp.getx().getintvalue() % self._curve.getn()
		assert(r != 0)

		s = ModInt(e + self._privkey * r, self._curve.getn()) // k

		return { "r" : r, "s" : s }

	def verify(self, message, r, s):
		# Calculate hash of message
		e = ECKeypair._bytestoint(hashlib.sha1(message.encode("utf-8")).digest())

		assert((r > 0) and (r < self._curve.getn()))
		assert((s.getintvalue() > 0) and (s.getintvalue() < self._curve.getn()))
		w = s.inverse()		
		u1 = e * w
		u2 = r * w
		
		pt = (u1 * self._curve.getG()) + (u2 * self._pubkey)
		x1 = pt.getx().getintvalue() % self._curve.getn()
		return x1 == r
		
	def __str__(self):
		return "Keypair Priv: 0x%x, Pub: %s" % (self._privkey, str(self._pubkey))


