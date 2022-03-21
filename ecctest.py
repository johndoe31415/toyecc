#!/usr/bin/python3
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

import sys

from toyecc import AffineCurvePoint, ShortWeierstrassCurve, getcurvebyname
from toyecc import ECPrivateKey

def separator():
	print("-" * 150)


usedcurve = getcurvebyname("secp112r1")
#usedcurve = getcurvebyname("brainpoolP160r1")
#usedcurve = getcurvebyname("secp192k1")
print("Selected curve parameters:")
print(str(usedcurve))
separator()

privatekey = ECPrivateKey(0x12345, usedcurve)
print("Generated privatekey")
print(str(privatekey))
separator()


########################### Encryption example ###########################
e = privatekey.pubkey.ecies_encrypt()
print("Encryption")
print("Transmitted R  :", e["R"])
print("Symmetric key S:", e["S"])
separator()

# And decrypt at receiver
print("Decryption")
recovered_s = privatekey.ecies_decrypt(e["R"])
print("Recovered S    :", recovered_s)
separator()


########################### Signature example ###########################
print("Signing message")
signature = privatekey.ecdsa_sign(b"foobar", "sha1")
print("r:", signature.r)
print("s:", signature.s)
separator()

print("Verification of signature")
verify_original = privatekey.pubkey.ecdsa_verify(b"foobar", signature)
verify_modified = privatekey.pubkey.ecdsa_verify(b"foobaz", signature)
print("Original message: %s (should be True)" % (verify_original))
print("Modified message: %s (should be False)" % (verify_modified))
assert(verify_original)
assert(not verify_modified)
separator()


########################### Identical-nonce-in-signature exploit ###########################
print("Generating signatures with identical nonces for exploitation")
signature1 = privatekey.ecdsa_sign(b"foobar", "sha1", k = 123456)
signature2 = privatekey.ecdsa_sign(b"foobaz", "sha1", k = 123456)

print("r1:", signature1.r)
print("s1:", signature1.s)
print("r2:", signature2.r)
print("s2:", signature2.s)
recvr = privatekey.pubkey.ecdsa_exploit_reused_nonce(b"foobar", signature1, b"foobaz", signature2)

print("Recovered nonce      :", int(recvr["nonce"]))
print("Recovered private key: 0x%x" % (int(recvr["privatekey"])))
separator()


########################### Finding arbitrary points on the curve ###########################
x = 123456
print("Finding points on the curve with x == %d" % (x))
points = usedcurve.getpointwithx(x)
if points:
	(pt1, pt2) = points
	print("Point 1:", pt1)
	print("Point 2:", pt2)
	print("On curve? %s/%s (should be True/True)" % (pt1.oncurve(), pt2.oncurve()))
	assert(pt1.oncurve())
	assert(pt2.oncurve())
else:
	print("No point found")
separator()


########################### Generating tiny curve for example purposes ###########################
print("Generating a tiny curve")
tinycurve = ShortWeierstrassCurve(
	2, 			# A
	3,	 		# B
	263, 		# p
	270,		# n (order)
	1,			# cofactor
	200,		# G_x
	39			# G_y
)
print(str(tinycurve))
print("Curve order is #E(F_p) = %d" % (tinycurve.curve_order))
print("Generator is of order %d" % (tinycurve.G.naive_order_calculation()))

print("Determining points of small order (weak points), this could take a while...")
for point in tinycurve.enumerate_points():
	order = point.naive_order_calculation()
	if order <= 6:
		print("%-20s order %d" % (str(point), order))
separator()


########################### Checking point compression ###########################
for randomnumber in range(125, 125 + 2):
	p = usedcurve.G * randomnumber
	print("Uncompressed point:", p)
	c = p.compress()
	print("Compressed point  :", c)
	u = usedcurve.uncompress(c)
	print("Uncompressed point:", u)
	assert(u == p)
	separator()



