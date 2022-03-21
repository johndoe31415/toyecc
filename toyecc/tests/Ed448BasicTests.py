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
from .. import FieldElement, getcurvebyname, ECPublicKey, ECPrivateKey

class Ed448BasicTests(unittest.TestCase):
	def test_sign_verify(self):
		curves = [getcurvebyname("Ed448-Goldilocks"), getcurvebyname("Ed448")]
		for curve in curves:
			privkey = ECPrivateKey.eddsa_generate(curve)

			msg = b"foobar"
			signature = privkey.eddsa_sign(msg)

			self.assertTrue(privkey.pubkey.eddsa_verify(msg, signature))
			self.assertFalse(privkey.pubkey.eddsa_verify(msg + b"x", signature))

	def test_sig_encode_decode(self):
		curves = [ getcurvebyname("Ed448"), getcurvebyname("Ed448-Goldilocks") ]
		for curve in curves:
			privkey = ECPrivateKey.eddsa_generate(curve)
			msg = b"foobar"
			signature = privkey.eddsa_sign(msg)

			encoded_signature = signature.encode()
			decoded_signature = ECPrivateKey.EDDSASignature.decode(curve, encoded_signature)
			self.assertEqual(decoded_signature, signature)
			self.assertTrue(privkey.pubkey.eddsa_verify(msg, signature))
			self.assertTrue(privkey.pubkey.eddsa_verify(msg, decoded_signature))

	def test_seeding_signing(self):
		curve = getcurvebyname("Ed448-Goldilocks")
		seed = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")

		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)
		self.assertEqual(privkey.seed, seed)
		self.assertEqual(privkey.scalar, 521658399617511624509929819094270498323007786671637499019582168374758478770958028340603419308639592898868374490003595203618871291427304)

		pubkey = privkey.pubkey
		self.assertEqual(pubkey.point.x, 0xf6882451bdd0174e32c5b38a637659cd839ef9cc40b53843adda3b01886a86edc71e8af14839b8bb21e185775ed3f61a105d0bf339d04ac7)
		self.assertEqual(pubkey.point.y, 0xca023dfc9ed27809e1ca6976cb18618cf066bdd0769dd8962bac9c9535c7bf092090dfa289a997a332ed9c3984ed085dbf9dce6effb489d6)

		msg = b"Foobar!"
		signature = privkey.eddsa_sign(msg)

		self.assertEqual(signature.R.x, 0x6e9acf5065ca854d5d492b85e9178cbad79646ad450eee2a033b8ae7185b8baee834d37726964954cc66d732c52748e3dfdd63d032960e98)
		self.assertEqual(signature.R.y, 0x1d460c01a5a31d3ee5271be4295464cfcb1b8354c6ba09e95c9d440b6eb0cfa3733c40bff6b8384b3eec45686d222e511e6b133db4203b10)
		self.assertEqual(signature.s, 0x325c4c3d9fe2873c6ba8e403abe00543d9b2245599036e32fc10b83e86019bb8bacb78ded80b70a923d2fa1a7ca606639418082cb352014c)

	def test_key_encoding(self):
		curve = getcurvebyname("Ed448-Goldilocks")
		seed = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")

		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)

		self.assertEqual(privkey.eddsa_encode(), bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"))
		self.assertEqual(privkey.pubkey.eddsa_encode(), bytes.fromhex("d689b4ff6ece9dbf5d08ed84399ced32a397a989a2df902009bfc735959cac2b96d89d76d0bd66f08c6118cb7669cae10978d29efc3d02ca80"))

	def test_key_decoding(self):
		curve = getcurvebyname("Ed448-Goldilocks")
		seed = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")

		privkey = ECPrivateKey.eddsa_decode(curve, bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"))
		self.assertEqual(privkey.seed, seed)
		self.assertEqual(privkey.scalar, 521658399617511624509929819094270498323007786671637499019582168374758478770958028340603419308639592898868374490003595203618871291427304)

		pubkey = ECPublicKey.eddsa_decode(curve, bytes.fromhex("71c7391d7a5df8dc1aa14fae59256e7bbf4b4f12065a435f7fe0b36a71de0db7e09d32074ad2baa5773f16f85c1171945912f5b08a0990b900"))

	def test_keys_ed448_rfc8032(self):
		curve = getcurvebyname("Ed448")

		# RFC8032 testvector 1
		seed = bytes.fromhex("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b")
		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)
		self.assertEqual(privkey.seed, seed)
		self.assertEqual(privkey.scalar, 521658399617511624509929819094270498323007786671637499019582168374758478770958028340603419308639592898868374490003595203618871291427304)

		pubkey = privkey.pubkey
		self.assertEqual(pubkey.point.x, 0xb02f7d0580fd8e88f3fc8ecd47f43499b0000faf1e84d0c2283736c991c4a64447ce4e8d8a6c74010baf726ef20006bcf1fa990e7a822287)
		self.assertEqual(pubkey.point.y, 0x6125e8afbe1afad16c0fe5f13d78d61b06c7469b7624f1ed7867e9805da70e8a1f0ea7852434a11d6ad46a61ec87e72cfd61b4599b44d75f)
		self.assertEqual(pubkey.eddsa_encode(), bytes.fromhex("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"))

		msg = b"Foobar!"
		signature = privkey.eddsa_sign(msg)

		self.assertEqual(signature.R.x, 0xe7ff455957ad25768b75c9257fd9757706aa473061636eebfb24cc54fd944fe7e2aa8b07283a30e8c2d96a357b17c7e6ba83f6ece4f0ff17)
		self.assertEqual(signature.R.y, 0xc49a90fb910f4e6eb4a25ad3dc76d8e2f273d8a3b738374dc1310e7b6fd71185d96aa47c2436b63a64924da58879ccdb9437e026521692be)
		self.assertEqual(signature.s, 0x37754cfdfce43e25c7a49b7cbd18bbbfa2746e154d5f82a00ae274dcc5c88329eb7e51f6ccdc29cc4cf0d4bc05ad5a4c8f39ce6275dbbf4)

		# RFC8032 testvector 2
		seed = bytes.fromhex("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e")
		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)
		self.assertEqual(privkey.seed, seed)
		self.assertEqual(privkey.scalar, 689909312335174883516499642766841446935258538413003095779028193821563285076416857945471525085401816906939882844448039967110836770482568)

		pubkey = privkey.pubkey
		self.assertEqual(pubkey.point.x, 0xd2ffd9b53d3bff141f68cf0248020a14e2f1aba433258c33c290607f78eab2c6b969bdf226775ba7db74bcf20ffddab9d3ada6b23a0ee857)
		self.assertEqual(pubkey.point.y, 0x943a4c7b626051239c1682cba48e43b802287400eb01ea6a86c098676c0cfa2b37c058935da534c80acd7e5f5431e56a45ffcd30f428ba43)
		self.assertEqual(pubkey.eddsa_encode(), bytes.fromhex("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"))
