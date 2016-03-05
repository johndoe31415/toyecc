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

import hashlib

def bytestoint(data):
	"""Converts given bytes to a big-endian integer value."""
	return sum(value << (8 * index) for (index, value) in enumerate(reversed(data)))

def bytestoint_le(data):
	"""Converts given bytes to a little-endian integer value."""
	return sum(value << (8 * index) for (index, value) in enumerate(data))

def inttobytes_le(value, length):
	"""Converts a little-endian integer value into a bytes object."""
	return bytes((value >> (8 * i)) & 0xff for i in range(length))

def ecdsa_msgdigest_to_int(message_digest, curveorder):
	"""Performs truncation of a message digest to the bitlength of the curve
	order."""
	# Convert message digest to integer value
	e = bytestoint(message_digest)

	# Truncate hash value if necessary
	msg_digest_bits = 8 * len(message_digest)
	if msg_digest_bits > curveorder.bit_length():
		shift = msg_digest_bits - curveorder.bit_length()
		e >>= shift

	return e

def eddsa_hash(data):
	"""Returns the message digest over the data which is used for EdDSA
	(SHA-512)."""
	return hashlib.sha512(data).digest()

