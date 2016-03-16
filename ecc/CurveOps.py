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

from .FieldElement import FieldElement

class CurveOpIsomorphism(object):
	def isomorphism(self, u):
		"""Returns a isomorphous curve by applying the transformation x -> u²x
		and y -> u³y."""
		assert(self.curvetype == "shortweierstrass")
		ShortWeierstrassCurve = self.__class__
		if u == 0:
			raise Exception("Domain error: u must be nonzero.")

		u = FieldElement(u, self.p)
		a = self.a * (u ** 4)
		b = self.b * (u ** 6)
		if self.hasgenerator:
			Gx = int(self.G.x * (u ** 2))
			Gy = int(self.G.y * (u ** 3))
		else:
			Gx = None
			Gy = None
		return ShortWeierstrassCurve(a = int(a), b = int(b), p = self.p, n = self.n, h = self.h, Gx = Gx, Gy = Gy)

	def isomorphism_fixed_a(self, a):
		"""Tries to find an isomorphous curve which has a particular value for
		the curve coefficient a."""

		# anew = a * u^4 -> u = sqrt4(anew / a)
		scalar = a // self.a
		u = scalar.sqrt4()
		if u is None:
			raise Exception("Cannot find an isomorphism so that a = %d because %s has no quartic root in F_P" % (a, scalar))
		return self.isomorphism(int(u))

class CurveOpExportSage(object):
	def export_sage(self, varname = "curve"):
		"""Exports the elliptic curve to statements that can be used within the
		SAGE computer algebra system."""

		# EllipticCurve([a1,a2,a3,a4,a6]) means in Sage:
		# y² + a1 x y + a3 y = x³ + a2 x² + a4 x + a6
		# i.e. for Short Weierstrass a4 = A, a6 = B

		statements = [ ]
		statements.append("# %s" % (str(self)))
		statements.append("%s_p = 0x%x" % (varname, int(self.p)))
		statements.append("%s_F = GF(%s_p)" % (varname, varname))
		if self.curvetype == "shortweierstrass":
			statements.append("%s_a = 0x%x" % (varname, int(self.a)))
			statements.append("%s_b = 0x%x" % (varname, int(self.b)))
			statements.append("%s = EllipticCurve(%s_F, [ %s_a, %s_b ])" % (varname, varname, varname, varname))
		else:
			raise Exception(NotImplemented)

		return statements
