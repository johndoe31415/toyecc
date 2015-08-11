from .PubKeyOps import PubKeyOpECDSAVerify, PubKeyOpECDSAExploitReusedNonce, PubKeyOpEDDSAVerify, PubKeyOpEDDSAEncode, PubKeyOpECIESEncrypt

class ECPublicKey(PubKeyOpECDSAVerify, PubKeyOpECDSAExploitReusedNonce, PubKeyOpEDDSAVerify, PubKeyOpEDDSAEncode, PubKeyOpECIESEncrypt):
	"""Elliptic curve public key abstraction. An EC public key is just a point
	on the curve, which is why the constructor only takes this (public) point
	as a parameter. The public key abstraction allows this point to be used in
	various meaningful purposes (ECDSA signature verification, etc.)."""

	def __init__(self, point):
		self._point = point

	@property
	def curve(self):
		return self._point.curve

	@property
	def point(self):
		return self._point

	def __str__(self):
		return "PublicKey<%s>" % (str(self.point))
