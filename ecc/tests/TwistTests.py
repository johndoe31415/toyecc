#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2015 Johannes Bauer
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

import unittest
from .. import getcurvebyname, ShortWeierstrassCurve

class TwistTests(unittest.TestCase):
	def test_brainpool_gf_p_isomorphism(self):
		curve_lengths = (160, 192, 224, 256, 320, 384, 512)
		for bitlen in curve_lengths:
			name_orig = "brainpoolP%dr1" % (bitlen)
			name_twist = "brainpoolP%dt1" % (bitlen)
			curve = getcurvebyname(name_orig)
			twist = getcurvebyname(name_twist)
			self.assertTrue(curve.is_isomorphous_curve(twist))

			my_twist = curve.twist_fp_isomorphic_fixed_a(-3)
			self.assertEqual(my_twist.a, -3)
			self.assertEqual(my_twist.b, twist.b)
			self.assertTrue(twist.is_isomorphous_curve(my_twist))

	def test_brainpool_twist(self):
		curve = getcurvebyname("secp112r1")

		# Known twists as calculated by SAGE
		known_twist_1 = ShortWeierstrassCurve.init_rawcurve(0xa6fd184bb33a605361d692c0847d, 0x8cc213474426835665f6814abac1, curve.p)
		known_twist_2 = ShortWeierstrassCurve.init_rawcurve(0x1d18972a37f1746e92a1083a31fc, 0x395862918bf1a0fdff444ea0a8be, curve.p)
		known_twist_3 = ShortWeierstrassCurve.init_rawcurve(0x2a0b265cc68e756c04317c260af1, 0x9457ee33ea0aceb330ab19a8b7a3, curve.p)
		for i in range(10):
			twist = curve.twist()
			self.assertTrue(twist.is_isomorphous_curve(known_twist_1))
			self.assertTrue(twist.is_isomorphous_curve(known_twist_2))
			self.assertTrue(twist.is_isomorphous_curve(known_twist_3))

