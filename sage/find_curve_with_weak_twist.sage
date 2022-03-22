#!/usr/bin/sage
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

import json
import os
from cysignals.alarm import alarm, AlarmInterrupt, cancel_alarm

p = 0x00ffffffff00000001000000000000000000000000ffffffffffffffffffffffff
filename = "curves_with_weak_twist_" + os.urandom(8).hex() + ".json"

def find_nonsquare_mod_p(p):
	F = GF(p)
	while True:
		d = F(randint(2, p - 1))
		if not d.is_square():
			return d

def found_curve(E, n, Et, nt, twist_bits):
	try:
		with open(filename) as f:
			results = json.load(f)
	except FileNotFoundError:
		results = [ ]

	result = {
		"curve": {
			"n": int(n),
			"a": int(E.a4()),
			"b": int(E.a6()),
			"p": int(E.base_field().order()),
		},
		"twist": {
			"n": int(nt),
			"a": int(Et.a4()),
			"b": int(Et.a6()),
			"bits": int(twist_bits),
		}
	}
	results.append(result)
	print("E", E, "has prime order", n, "twist bits", bits)

	with open(filename, "w") as f:
		json.dump(results, f)


Fp = GF(p)
print("Searching for curve parameters with prime order curve but weak twist, p = %d" % (p))
a = 3
while True:
	b = randint(3, p - 1)
	try:
		E = EllipticCurve(Fp, [a, b])
	except ArithmeticError:
		# Singular curve
		continue

	n = E.order()
	if is_prime(n):
		Et = EllipticCurve(Fp, [ d^2*a, d^3*b ])
		nt = Et.order()

		try:
			alarm(30)
			q = nt.factor()
			greatest_prime = list(q)[-1][0]
			bits = int(greatest_prime).bit_length()
		except AlarmInterrupt:
			bits = -1
		else:
			cancel_alarm()
		found_curve(E, n, Et, nt, bits)
