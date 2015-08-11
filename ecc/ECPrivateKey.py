from .PrivKeyOps import PrivKeyOpECDSASign, PrivKeyOpECIESDecrypt, PrivKeyOpEDDSASign, PrivKeyOpEDDSAKeyGen, PrivKeyOpEDDSAEncode, PrivKeyOpECDH
from .ECPublicKey import ECPublicKey
from .Random import secure_rand_int_between

class ECPrivateKey(PrivKeyOpECDSASign, PrivKeyOpECIESDecrypt, PrivKeyOpEDDSASign, PrivKeyOpEDDSAKeyGen, PrivKeyOpEDDSAEncode, PrivKeyOpECDH):
	"""Represents an elliptic curve private key."""

	def __init__(self, scalar, curve):
		"""Initialize the private key with the given scalar on the given
		curve."""
		self._seed = None
		self._scalar = scalar
		self._curve = curve
		self._pubkey = ECPublicKey(self._scalar * self._curve.G)

	@property
	def scalar(self):
		"""Returns the private scalar d of the key."""
		return self._scalar

	@property
	def curve(self):
		"""Returns the group which is used for EC computations."""
		return self._curve

	@property
	def pubkey(self):
		"""Returns the public key that is the counterpart to this private key."""
		return self._pubkey

	@property
	def seed(self):
		"""Returns the seed or None if there wasn't one. A seed is used for
		schemes like EdDSA; it basically is a binary string that is hashed to
		yield that actual private scalar d."""
		return self._seed

	def set_seed(self, seed):
		"""Sets the seed of the private key. This operation can only performed
		if no scalar has previously been set for this key."""
		assert(self._seed is None)
		self._seed = seed
		return self

	@staticmethod
	def generate(curve):
		"""Generate a random private key on a given curve."""
		scalar = secure_rand_int_between(1, curve.n - 1)
		return ECPrivateKey(scalar, curve)

	def __str__(self):
		if self._seed is None:
			return "PrivateKey<d = 0x%x>" % (self.scalar)
		else:
			seedstr = "".join("%02x" % (c) for c in self._seed)
			return "PrivateKey<d = 0x%x, seed = %s>" % (self.scalar, seedstr)

