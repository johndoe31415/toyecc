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

