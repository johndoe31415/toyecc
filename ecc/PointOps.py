from . import Tools
from .FieldElement import FieldElement

class PointOpEDDSAEncoding(object):
	def eddsa_encode(self):
		"""Performs serialization of the point as required by EdDSA."""
		bitlen = self.curve.p.bit_length()
		enc_value = int(self.y)
		enc_value &= ((1 << bitlen) - 1)
		enc_value |= (int(self.x) & 1) << bitlen
		return Tools.inttobytes_le(enc_value, self.curve.B // 8)

	@staticmethod
	def __eddsa_recoverx(curve, y):
		xx = (y * y - 1) // (curve.d * y * y + 1)
		x = xx ** ((curve.p + 3) // 8)
		if x * x != xx:
			I = FieldElement(-1, curve.p).sqrt()[0]
			x = x * I
		if (int(x) % 2) != 0:
			x = -x
		return int(x)

	@classmethod
	def eddsa_decode(cls, curve, data):
		"""Performs deserialization of the point as required by EdDSA."""
		assert(curve.curvetype == "twistededwards")
		bitlen = curve.p.bit_length()
		enc_value = Tools.bytestoint_le(data)
		y = enc_value & ((1 << bitlen) - 1)
		x = PointOpEDDSAEncoding.__eddsa_recoverx(curve, y)
		hibit = (enc_value >> bitlen) & 1
		if (x & 1) != hibit:
			x = curve.p - x
		return cls(x, y, curve)

class PointOpCurveConversion(object):
	@staticmethod
	def __pconv_twed_mont_scalefactor(twedcurve, montcurve):
		native_b = 4 // (twedcurve.a - twedcurve.d)
		if native_b == montcurve.b:
			# Scaling is not necessary, already native curve format
			scale_factor = 1
		else:
			# Scaling of montgomery y component (v) is needed
			if twedcurve.hasgenerator and montcurve.hasgenerator:
				# Convert the generator point of the twisted edwards source
				# point to unscaled Montgomery space
				Gv = (1 + twedcurve.G.y) // ((1 - twedcurve.G.y) * twedcurve.G.x)

				# And calculate a multiplicative scaling factor so that the
				# point will result in the target curve's generator point Y
				scale_factor = montcurve.G.y // Gv

			elif native_b.is_qr:
				# If b is a quadradic residue mod p then any other
				# quadratic residue can serve as a surrgate b coefficient
				# to yield an isomorphous curve. Only y coordinate of the
				# resulting points needs to be scaled. Calculate a scaling
				# ratio.
				scale_factors = (montcurve.b // native_b).sqrt()

				# At least one of the curves lacks a generator point,
				# select just any scale factor
				scale_factor = scale_factors[0].inverse()

			else:
				# Native B is a quadratic non-residue module B; Not sure
				# how to handle this case
				# TODO: Implement this
				raise Exception(NotImplemented)
		return scale_factor

	def convert(self, targetcurve):
		"""Convert the affine curve point to a point on a birationally
		equivalent target curve."""

		if self.is_neutral:
			return targetcurve.neutral()

		if (self.curve.curvetype == "twistededwards") and (targetcurve.curvetype == "montgomery"):
			# (x, y) are Edwards coordinates
			# (u, v) are Montgomery coordonates
			(x, y) = (self.x, self.y)
			u = (1 + y) // (1 - y)
			v = (1 + y) // ((1 - y) * x)

			# Montgomery coordinates are unscaled to the actual B coefficient
			# of the curve right now. Calculate scaling factor and scale v
			# appropriately
			scaling_factor = self.__pconv_twed_mont_scalefactor(self.curve, targetcurve)
			v = v * scaling_factor

			point = self.__class__(int(u), int(v), targetcurve)
		elif (self.curve.curvetype == "montgomery") and (targetcurve.curvetype == "twistededwards"):
			# (x, y) are Edwards coordinates
			# (u, v) are Montgomery coordonates
			(u, v) = (self.x, self.y)
			y = (u - 1) // (u + 1)
			x = -(1 + y) // (v * (y - 1))

			# Twisted Edwards coordinates are unscaled to the actual B
			# coefficient of the curve right now. Calculate scaling factor and
			# scale x appropriately
			scaling_factor = self.__pconv_twed_mont_scalefactor(targetcurve, self.curve)
			x = x * scaling_factor

			point = self.__class__(int(x), int(y), targetcurve)
		else:
			raise Exception(NotImplemented)

		assert(point.oncurve())
		return point

class PointOpNaiveOrderCalculation(object):
	def naive_order_calculation(self):
		"""Calculates the order of the point naively, i.e. by walking through
		all points until the given neutral element is hit. Note that this only
		works for smallest of curves and is not computationally feasible for
		anything else."""
		curpt = self
		order = 1
		while not curpt.is_neutral:
			order += 1
			curpt += self
		return order

