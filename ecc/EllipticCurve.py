from .AffineCurvePoint import AffineCurvePoint

class EllipticCurve(object):
	"""Elliptic curve base class. Provides functionality which all curves have
	in common."""

	@property
	def curve_order(self):
		"""Returns the order of the curve, i.e. #E(F_p). Intuitively, this is
		the total number of points on the curve (plus maybe points at ininity,
		depending on the curve type) that satisfy the curve equation."""
		return self.h * self.n

	@property
	def domainparams(self):
		"""Returns the curve parameters as a named tuple."""
		raise Exception(NotImplemented)

	@property
	def hasgenerator(self):
		"""Returns if a generator point was supplied for the curve."""
		return self.G is not None

	@property
	def hasname(self):
		"""Returns if the curve is named (i.e. its name is not None)."""
		return self.name is not None

	@property
	def name(self):
		"""Returns the name of the curve, if it was given one during
		construction. Purely informational."""
		return self._name

	@property
	def curvetype(self):
		"""Returns a string that corresponds to the curve type. For example,
		this string can be 'shortweierstrass', 'twistededwards' or
		'montgomery'."""
		raise Exception(NotImplemented)
	
	def enumerate_points(self):
		"""Enumerates all points on the curve, including the point at infinity
		(if the curve has such a special point)."""
		raise Exception(NotImplemented)

	def naive_order_calculation(self):
		"""Naively calculates the order #E(F_p) of the curve by enumerating and
		counting all points which fulfull the curve equation. Note that this
		implementation only works for the smallest of curves and is
		computationally infeasible for all practical applications."""
		order = 0
		for pt in self.enumerate_points():
			order += 1
		return order

	def neutral(self):
		"""Returns the neutral element of the curve group (for some curves,
		this will be the point at infinity)."""
		return AffineCurvePoint(None, None, self)

	def is_neutral(self, P):
		"""Checks if a given point P is the neutral element of the group."""
		return P.x is None

	def oncurve(self, P):
		"""Checks is a given point P is on the curve."""
		raise Exception(NotImplemented)

	def point_addition(self, P, Q):
		"""Returns the sum of two points P and Q on the curve."""
		raise Exception(NotImplemented)

	def compress(self, P):
		"""Returns the compressed representation of the point P on the
		curve. Not all curves may support this operation."""
		raise Exception(NotImplemented)

	def uncompress(self, compressed):
		"""Returns the uncompressed representation of a point on the curve. Not
		all curves may support this operation."""
		raise Exception(NotImplemented)

	def __eq__(self, other):
		return self.domainparams == other.domainparams

	def __ne__(self, other):
		return not (self == other)

