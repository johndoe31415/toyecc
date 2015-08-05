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
from .. import getcurvebyname, getcurvenames
from ..ECKeypair import ECDSASignature

class CryptoOpsTests(unittest.TestCase):
	def test_curve_integrity(self):
		for curvename in getcurvenames():
			curve = getcurvebyname(curvename)
			self.assertTrue(curve.G.oncurve())

	def test_simple_sign_verify(self):
		curve = getcurvebyname("secp112r1")
		keypair = curve.genknownkeypair(0xdeadbeef)
		self.assertEqual(int(keypair.pubkey.x), 3029259716094196738484362740763961)
		self.assertEqual(int(keypair.pubkey.y), 2918181739692718713384134377830669)

		msg = b"foobar"
		signature = keypair.sign_msg(msg, "sha1", k = 12345)
		self.assertEqual(signature.s, 1960761230049936699759766101723490)
		self.assertEqual(signature.r, 1696427335541514286367855701829018)

		self.assertTrue(keypair.verify_msg(msg, signature))

	def test_openssl_signature(self):
		curve = getcurvebyname("prime239v1")
		msg = b"foobar"
		r = 0x76EAA8341A6E30FE72C87343A50DD2BBE472CF5E5A394D245DF354EF11CD
		s = 0x0304117012F37FC316D9030E456F53940008C7FAF569BBE6E5B4AA1A2D40
		hashalg = "sha256"

		privkey = "6e:29:dc:d3:c4:7c:a3:3c:3d:0e:f5:3a:15:14:18:ff:ff:9b:44:dc:26:21:ac:d3:fc:ac:ca:5b:c8:f2"
		privkey = int(privkey.replace(":", ""), 16)
		keypair = curve.genknownkeypair(privkey)
		self.assertEqual(int(keypair.pubkey.x), 0x0f5e2baa05719806cbdb133d438011efc2c4e036d59cb799fa87d2ecab97)
		self.assertEqual(int(keypair.pubkey.y), 0x56fd18e031e2869a872bbc96ec473bd5eb2e9a22a2e246bd00ed0491fdde)

		signature = ECDSASignature(r = r, s = s, hashalg = hashalg)
		self.assertTrue(keypair.verify_msg(msg, signature))
