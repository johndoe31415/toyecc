#!/usr/bin/python3
#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2011 Johannes Bauer
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

import sys

from AffineCurvePoint import AffineCurvePoint
from EllipticCurve import EllipticCurve

def separator():
	print("-" * 150)


curves = { 
			"brainpoolP160r1": EllipticCurve(
				0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300, 		# A
				0x1E589A8595423412134FAA2DBDEC95C8D8675E58, 		# B
				0xE95E4A5F737059DC60DFC7AD95B3D8139515620F, 		# p
				0xE95E4A5F737059DC60DF5991D45029409E60FC09,			# n (order)
				1,													# cofactor
				0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3,			# G_x
				0x1667CB477A1A8EC338F94741669C976316DA6321			# G_y
			),
			"secp112r1": EllipticCurve(
				0xdb7c2abf62e35e668076bead2088, 		# A
				0x659ef8ba043916eede8911702b22, 		# B
				0xdb7c2abf62e35e668076bead208b, 		# p
				0xdb7c2abf62e35e7628dfac6561c5,			# n (order)
				1,										# cofactor
				0x09487239995a5ee76b55f9c2f098,			# G_x
				0xa89ce5af8724c0a23e0e0ff77500			# G_y
			),
			"secp192k1": EllipticCurve(
				0,											 		# A
				3, 													# B
				0xfffffffffffffffffffffffffffffffffffffffeffffee37, # p
				0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d,	# n (order)
				1,													# cofactor
				0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d,	# G_x
				0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d	# G_y
			)
}
#usedcurve = curves["brainpoolP160r1"]
usedcurve = curves["secp112r1"]
#usedcurve = curves["secp192k1"]
print("Selected curve parameters")
print(str(usedcurve))
separator()

keypair = usedcurve.genknownkeypair(0x12345)
print("Generated keypair")
print(str(keypair))
separator()


########################### Encryption example ###########################
e = keypair.encrypt()
print("Encryption")
print("Transmitted R  :", e["R"])
print("Symmetric key S:", e["S"])
separator()

# And decrypt at receiver
print("Decryption")
recovered_s = keypair.decrypt(e["R"])
print("Recovered S    :", recovered_s)
separator()


########################### Signature example ###########################
print("Signing message")
signature = keypair.sign("foobar")
print("r:", signature["r"])
print("s:", signature["s"])
separator()

print("Verification of signature")
print("Original message:", keypair.verify("foobar", signature["r"], signature["s"]))
print("Modified message:", keypair.verify("foobaz", signature["r"], signature["s"]))
separator()


########################### Identical-nonce-in-signature exploit ###########################
print("Generating signatures with identical nonces for exploitation")
signature1 = keypair.sign("foobar", 123456)
signature2 = keypair.sign("foobaz", 123456)

print("r1:", signature1["r"])
print("s1:", signature1["s"])
print("r2:", signature2["r"])
print("s2:", signature2["s"])
recvr = usedcurve.exploitidenticalnoncesig(signature1["r"], signature1["s"], "foobar", signature2["s"], "foobaz")

print("Recovered nonce      :", recvr["nonce"])
print("Recovered private key: 0x%x" % (recvr["privatekey"].getintvalue()))
separator()


########################### Finding arbitrary points on the curve ###########################
x = 123456
print("Finding points on the curve with x == %d" % (x))
points = usedcurve.getpointwithx(x)
if points:
	(pt1, pt2) = points
	print("Point 1:", pt1)
	print("Point 2:", pt2)
	print("On curve?", pt1.oncurve(), pt2.oncurve())
else:
	print("No point found")
separator()


########################### Generating tiny curve for example purposes ###########################
print("Generating a tiny curve")
tinycurve = EllipticCurve(
	2, 			# A
	3,	 		# B
	263, 		# p
	270,		# n (order)
	1,			# cofactor
	200,		# G_x
	39			# G_y
)
print(str(tinycurve))
print("Curve is of order", tinycurve.countpoints())

determine_all_points = False		# This takes long
walk_generator_points = False		# This takes long

if determine_all_points:
	points = set()
	g = None
	for x in range(tinycurve.getp()):
		p = tinycurve.getpointwithx(x)
		if p:
			print(p[0], p[1])
			points.add(p[0])
			points.add(p[1])
	print("Curve has %d distinct points (plus one at infinity)." % (len(points)))


if determine_all_points and walk_generator_points:
	pointorders = { }
	while len(points) > 0:
		rdpt = points.pop()
		print("Randomly selected curve point:", rdpt)

		curpt = rdpt.clone()
		order = 1
		while not curpt.infinity():
			curpt += rdpt
			order += 1
		pointorders[order] = pointorders.get(order, set())
		pointorders[order].add(rdpt)

	for order in sorted(pointorders.keys()):
		print("Points with order %d:" % (order))
		for point in sorted(pointorders[order]):
			print("   %s" % (str(point)))


separator()


########################### Checking point compression ###########################
for randomnumber in range(125, 125 + 2):
	p = usedcurve.getG() * randomnumber
	print("Uncompressed point:", p)
	c = p.compress()
	print("Compressed point  :", c)
	u = AffineCurvePoint(None, None, usedcurve).uncompress(c)
	print("Uncompressed point:", u)
	assert(u == p)
	separator()



########################### Example on the webpage ###########################
secp192k1 = curves["secp192k1"]
recvr = secp192k1.exploitidenticalnoncesig(
	0xB44654432124B9EE0CAE954630AE09B5FB0D81A350005F25,
	0xB0035643E4C581DC089278F4E661F0FB7F98F14E8FA81785,
	"foo",
	0x3EE09F92DD92BBCAE1BFFB9708115E66850A2AD33F394DD8,
	"bar"
)
print("Recovered nonce      : 0x%x" % (recvr["nonce"].getintvalue()))
print("Recovered private key: 0x%x" % (recvr["privatekey"].getintvalue()))


