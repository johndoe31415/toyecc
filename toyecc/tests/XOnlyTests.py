#
#	toyecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2022 Johannes Bauer
#
#	This file is part of toyecc.
#
#	toyecc is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	toyecc is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with toyecc; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#

import unittest
from .. import getcurvebyname, ECPrivateKey, ShortWeierstrassCurve, AffineCurvePoint

class XOnlyTests(unittest.TestCase):
	def test_xonly_mul(self):
		curve = getcurvebyname("secp112r1")
		privkey = ECPrivateKey.generate(curve)
		x = curve.G.scalar_mul_xonly(privkey.scalar)
		self.assertEqual(x, privkey.pubkey.point.x)

	def test_small_subgroup_P2(self):
		curve = ShortWeierstrassCurve(p = 101, a = 3, b = 9, Gx = 0, Gy = 3, h = 1, n = 114)
		P2 = AffineCurvePoint(55, 0, curve)
		self.assertEqual(P2.scalar_mul_xonly(0), None)
		self.assertEqual(P2.scalar_mul_xonly(1), 55)
		self.assertEqual(P2.scalar_mul_xonly(2), None)
		self.assertEqual(P2.scalar_mul_xonly(3), 55)

	def test_small_subgroup_P3(self):
		curve = ShortWeierstrassCurve(p = 101, a = 3, b = 9, Gx = 0, Gy = 3, h = 1, n = 114)
		P3 = AffineCurvePoint(18, 21, curve)
		for i in range(20):
			j = i % 3
			if j == 0:
				self.assertEqual(P3.scalar_mul_xonly(i), None)
			else:
				self.assertEqual(P3.scalar_mul_xonly(i), 18)

	def test_small_subgroup_P6(self):
		curve = ShortWeierstrassCurve(p = 101, a = 3, b = 9, Gx = 0, Gy = 3, h = 1, n = 114)
		P6 = AffineCurvePoint(99, 46, curve)
		for i in range(20):
			j = i % 6
			if j == 0:
				self.assertEqual(P6.scalar_mul_xonly(i), None)
			elif j == 1:
				self.assertEqual(P6.scalar_mul_xonly(i), 0x63)
			elif j == 2:
				self.assertEqual(P6.scalar_mul_xonly(i), 0x12)
			elif j == 3:
				self.assertEqual(P6.scalar_mul_xonly(i), 0x37)
			elif j == 4:
				self.assertEqual(P6.scalar_mul_xonly(i), 0x12)
			else:
				self.assertEqual(P6.scalar_mul_xonly(i), 0x63)
