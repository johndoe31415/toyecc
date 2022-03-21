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

from toyecc import getcurvebyname, ECPrivateKey

curve = getcurvebyname("secp112r1")
print("Selected curve:", curve)

has_backdoor = True

# Non-backdoored implementation
if not has_backdoor:
	P = ECPrivateKey.generate(curve).pubkey.point
	Q = ECPrivateKey.generate(curve).pubkey.point
	print("Dual_EC_DBRG implementation is not backdoored")
else:
	P = ECPrivateKey.generate(curve).pubkey.point
	d = 987654321
	Q = d * P
	dinv = pow(d, -1, curve.n)
	print("Dual_EC_DBRG implementation is backdoored (d = %d, d^{-1} = %d)" % (d, dinv))
	print("Backdoor prerequisite: Q = d P")

print("P", P)
print("Q", Q)

print()

t = 0x123456789		# Initial state
print("Initial state:", hex(t))

s = int((t * P).x)
print("s            :", hex(s))

t = int((s * P).x)
sQ = s * Q
r = int(sQ.x)
print("sQ           :", sQ)
print("New state    :", hex(t))
print("Output       :", hex(r))

if has_backdoor:
	print()
	print("Recovered point from r:")
	(A, B) = curve.getpointwithx(r)
	print(A * dinv)
	print(B * dinv)
