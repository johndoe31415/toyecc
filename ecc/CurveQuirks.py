class CurveQuirk(object):
	identifier = None

	@property
	def identity(self):
		return (self.identifier, )

	def __eq__(self, other):
		return self.identity == other.identity

	def __ne__(self, other):
		return not (self == other)

	def __lt__(self, other):
		return self.identity < other.identity

	def __hash__(self):
		return hash(self.identity)

	def __str__(self):
		return self.identifier

class CurveQuirkEdDSASetPrivateKeyMSB(CurveQuirk):
	"""Set the highest significant bit of the private key during EdDSA
	signature generation. For example, for EdDSA signatures on Ed25519, this
	would bitwise or the value 'a' with 2^254."""
	identifier = "EdDSA_set_private_key_MSB"

class CurveQuirkEdDSAEnsurePrimeOrderSubgroup(CurveQuirk):
	"""Ensures during EdDSA signature generation that the private key is on a
	prime-order subgroup. This is done by clearing the amount of bits that is
	required by the cofactor of the curve (which has to be a power of two for
	this quirk to work, otherwise it'll fail at runtime). Concretely, for EdDSA
	on Ed25519 this means that the least significant three bits would be set to
	zero because the curve cofactor is 8."""
	identifier = "EdDSA_use_prime_order_subgroup"

