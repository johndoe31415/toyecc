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
		known_twist_1 = ShortWeierstrassCurve.init_rawcurve(0xdb7c2abf62e35e668076bead1bdb, 0xd6ce5ea491322bfe05c0d7022be3, curve.p, field_extension = 20)
		known_twist_2 = ShortWeierstrassCurve.init_rawcurve(0xdb7c2abf62e35e668076bead19cb, 0x684a8c3bd69e6065510ec0eb9900, curve.p, field_extension = 24)
		known_twist_3 = ShortWeierstrassCurve.init_rawcurve(0xdb7c2abf62e35e668076bead148b, 0x6d03b63b43341ad58bb247c1729f, curve.p, field_extension = 32)
		for i in range(10):
			twist = curve.twist()
			self.assertTrue(twist.is_isomorphous_curve(known_twist_1))
			self.assertTrue(twist.is_isomorphous_curve(known_twist_2))
			self.assertTrue(twist.is_isomorphous_curve(known_twist_3))

