import hashlib
import collections

from .FieldElement import FieldElement
from .Random import secure_rand, secure_rand_int_between
from .AffineCurvePoint import AffineCurvePoint
from . import Tools

class PrivKeyOpECDSASign(object):
	ECDSASignature = collections.namedtuple("ECDSASignature", [ "hashalg", "r", "s" ])

	def ecdsa_sign_hash(self, message_digest, k = None, digestname = None):
		"""Signs a given messagedigest, given as bytes, using ECDSA.
		Optionally a nonce k can be supplied which should usually be unqiuely
		chosen for every ECDSA signature. This way it is possible to
		deliberately create broken signatures which can be exploited later on.
		If k is not supplied, it is randomly chosen. If a digestname is
		supplied the name of this digest eventually ends up in the
		ECDSASignature object."""
		assert(isinstance(message_digest, bytes))
		assert((k is None) or isinstance(k, int))

		# Convert message digest to integer value
		e = Tools.ecdsa_msgdigest_to_int(message_digest, self.curve.n)

		# Select a random integer (if None is supplied!)
		if k is None:
			k = secure_rand_int_between(1, self.curve.n - 1)

		# r = (k * G)_x mod n
		Rmodp = k * self.curve.G
		r = int(Rmodp.x) % self.curve.n
		assert(r != 0)

		s = FieldElement(e + self.scalar * r, self.curve.n) // k

		return self.ECDSASignature(r = r, s = int(s), hashalg = digestname)

	def ecdsa_sign(self, message, digestname, k = None):
		"""Signs a given message with the digest that is given as a string.
		Optionally a nonce k can be supplied which should usually be unqiuely
		chosen for every ECDSA signature. This way it is possible to
		deliberately create broken signatures which can be exploited later
		on. If k is not supplied, it is randomly chosen."""
		assert(isinstance(message, bytes))
		assert(isinstance(digestname, str))
		digest_fnc = hashlib.new(digestname)
		digest_fnc.update(message)
		message_digest = digest_fnc.digest()
		return self.ecdsa_sign_hash(message_digest, k = k, digestname = digestname)


class PrivKeyOpECIESDecrypt(object):
	def ecies_decrypt(self, R):
		"""Takes the transmitted point R and reconstructs the shared secret
		point S using the private key."""
		# Transmitted R is given, restore the symmetric key S
		return self._scalar * R


class PrivKeyOpEDDSASign(object):
	class EDDSASignature(object):
		def __init__(self, curve, R, s):
			self._curve = curve
			self._R = R
			self._s = s

		@property
		def curve(self):
			return self._curve

		@property
		def R(self):
			return self._R

		@property
		def s(self):
			return self._s

		def encode(self):
			"""Performs serialization of the signature as used by EdDSA."""
			return self.R.eddsa_encode() + Tools.inttobytes_le(self.s, self.curve.B // 8)

		@classmethod
		def decode(cls, curve, encoded_signature):
			"""Performs deserialization of the signature as used by EdDSA."""
			assert(isinstance(encoded_signature, bytes))
			assert(len(encoded_signature) == 64)
			encoded_R = encoded_signature[:32]
			encoded_s = encoded_signature[32:]
			R = AffineCurvePoint.eddsa_decode(curve, encoded_R)
			s = Tools.bytestoint_le(encoded_s)
			return cls(curve, R, s)

		def __eq__(self, other):
			return (self.R, self.s) == (other.R, other.s)

		def __str__(self):
			return "EDDSASignature<R = %s, s = %s>" % (self.R, self.s)

	@staticmethod
	def __eddsa_hash(data):
		return hashlib.sha512(data).digest()

	@staticmethod
	def __eddsa_bitof(data, bitno):
		return (data[bitno // 8] >> (bitno % 8)) & 1

	def eddsa_sign(self, message):
		"""Performs an EdDSA signature of the message. For this to work the
		curve has to be a twisted Edwards curve and the private key scalar has
		to be generated from a hashed seed. This hashed seed is automatically
		generated when a keypair is generated using, for example, the
		eddsa_generate() function instead of the regular key generation
		function generate()."""
		assert(self.curve.curvetype == "twistededwards")
		if self._seed is None:
			raise Exception("EDDSA requires a seed which is the source for calculation of the private key scalar.")
		h = self.__eddsa_hash(self._seed)
		r = Tools.bytestoint_le(self.__eddsa_hash(h[32 : 64] + message))
		R = r * self.curve.G
		s = (r + Tools.bytestoint_le(self.__eddsa_hash(R.eddsa_encode() + self.pubkey.point.eddsa_encode() + message)) * self.scalar) % self.curve.n
		sig = self.EDDSASignature(self.curve, R, s)
		return sig


class PrivKeyOpEDDSAKeyGen(object):
	@staticmethod
	def __eddsa_bitof(data, bitpos):
		return (data[bitpos // 8] >> (bitpos % 8)) & 1

	@staticmethod
	def __eddsa_bitstring(data, bitcnt):
		return sum((PrivKeyOpEDDSAKeyGen.__eddsa_bitof(data, bitpos)) << bitpos for bitpos in range(bitcnt))

	@classmethod
	def eddsa_generate(cls, curve, seed = None):
		"""Generates a randomly selected seed value. This seed value is then
		hashed using the EdDSA hash function (usually SHA512) and the resulting
		value is (slightly modified) used as the private key scalar. Since for
		EdDSA signing operations this seed value is needed, it is also stored
		within the private key."""
		if seed is None:
			seed = secure_rand(curve.B // 8)
		assert(isinstance(seed, bytes))
		assert(len(seed) == curve.B // 8)

		# Calculate hash over seed
		h = Tools.eddsa_hash(seed)

		# And generate scalar from hash over seed
		a = PrivKeyOpEDDSAKeyGen.__eddsa_bitstring(h, curve.p.bit_length())

		# Conditioning may occur for some curves. Detect this by name for now.
		if curve.name == "ed25519":
			# Condition lower three bits to be cleared and bit 254 to be set
			a &= 0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8
			a |= 0x4000000000000000000000000000000000000000000000000000000000000000

		privkey = cls(a, curve)
		privkey.set_seed(seed)
		return privkey


class PrivKeyOpEDDSAEncode(object):
	def eddsa_encode(self):
		"""Performs serialization of a private key that is used for EdDSA."""
		return self.seed

	@classmethod
	def eddsa_decode(cls, curve, encoded_privkey):
		"""Performs decoding of a serialized private key as it is used for EdDSA."""
		return cls.eddsa_generate(curve, encoded_privkey)

class PrivKeyOpECDH(object):
	def ecdh_compute(self, peer_pubkey):
		"""Compute the shared secret point using our own private key and the
		public key of our peer."""
		return self.scalar * peer_pubkey.point

