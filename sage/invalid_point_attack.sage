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

import random
import sys
import collections
import json
import time
import toyecc
import itertools

class InvalidPointAttack():
	CurveTwist = collections.namedtuple("CurveTwist", [ "coeffs", "a", "b", "curve", "d" ])

	def __init__(self, problem_json_filename):
		with open(problem_json_filename) as f:
			self._problem = json.load(f)

		self._p = self._problem["p"]
		self._Fp = GF(self._p)
		Fp2.<z> = GF(self._p^2)
		self._Fp2 = Fp2
		self._D = self._choose_D()
		self._E = self._choose_curve()
		self._Et = self._twist_curve(self._E, self._D)
		self._validate_twist()
		self._E2 = EllipticCurve(self._Fp2, [ self._E.a4(), self._E.a6() ])
		self._victim_curve = toyecc.ShortWeierstrassCurve(a = int(self._E.a4()), b = int(self._E.a6()), p = self._p, n = int(self._E.order()), h = None, Gx = None, Gy = None)
		self._crt_constraints = { }

	def _choose_D(self):
		if "d" not in self._problem:
			D = self._Fp(2)
			while D.is_square():
				D += 1
			assert(not D.is_square())
			print("Chose: D =", D)
			sys.exit(0)
		else:
			D = self._Fp(self._problem["d"])
		assert(not D.is_square())
		return D

	def _choose_curve(self):
		if ("a" in self._problem) and ("b" in self._problem):
			(a, b) = (self._Fp(self._problem["a"]), self._Fp(self._problem["b"]))
		else:
			for a in range(1, p):
				for b in range(1, p):
					try:
						E = EllipticCurve(self._Fp, [a, b])
						ahat = self._Fp(a) * D^2
						bhat = self._Fp(b) * D^3
						Et = EllipticCurve(self._Fp, [ ahat, bhat ])
					except ArithmeticError:
						continue
					if is_prime(E.order()) and (E.order() != p) and (not is_prime(Et.order())):
						print("a = %3d; b = %3d; |E| = %3d |E^D| = %s" % (a, b, E.order(), factor(Et.order())))
			print("Specify a, b in the self._problem before continuing.")
			sys.exit(0)
		return EllipticCurve(self._Fp, [ a, b ])

	def _twist_curve(self, curve, d):
		ahat = curve.a4() * d^2
		bhat = curve.a6() * d^3
		twist = EllipticCurve(curve.base_field(), [ ahat, bhat ])
		assert(twist.is_quadratic_twist(curve))
		return twist

	def _validate_twist(self):
		if ("ahat" in self._problem) and ("bhat" in self._problem):
			assert(self._problem["ahat"] == self._Et.a4())
			assert(self._problem["bhat"] == self._Et.a6())
		else:
			print("Problem does not specify ahat, bhat (%d, %d)." % (self._Et.a4(), self._Et.a6()))
			sys.exit(0)

	def _dump_curves(self):
		print("E ", self._E)
		print("Et", self._Et)
		print("E2 ", self._E2)
		print("a = %3d; b = %3d; |E| = %3d = %s" % (self._E.a4(), self._E.a6(), self._E.order(), factor(self._E.order())))
		print("d = %d" % (self._problem["d"]))
		print("secret = %d" % (self._problem["secret"]))
		print("|E^d| = %3d = %s" % (self._Et.order(), factor(self._Et.order())))

	def _get_e2_base_point(self):
		# Returns a point of twist order on E2
		while True:
			P = self._E2.lift_x(self._Fp2(random.randint(1, self._p - 1)))
			if P.order() == self._Et.order():
				return P
		return P2base

	@classmethod
	def _any_qnr(cls, p):
		Fp = GF(p)
		for d in range(2, p):
			d = Fp(d)
			if not d.is_square():
				return d

	@classmethod
	def _specific_twist(cls, curve, d):
		ahat = curve.a4() * d^2
		bhat = curve.a6() * d^3
		Et = EllipticCurve(curve.base_field(), [ ahat, bhat ])
		return Et

	def _debug_enumerate_curve_twists(self, curve):
		result = {
			"iso": set(),
			"twist": set(),
		}
		(a, b) = (curve.a4(), curve.a6())

		for d in range(1, curve.base_field().order() - 1):
			d = curve.base_field()(d)
			ahat = a * d^2
			bhat = b * d^3
			Et = EllipticCurve(curve.base_field(), [ ahat, bhat ])
			ct = self.CurveTwist(coeffs = (ahat, bhat), a = ahat, b = bhat, curve = Et, d = d)
			if d.is_square():
				result["iso"].add(ct)
			else:
				result["twist"].add(ct)
		return result

	def _debug_enumerate_curve_twists_recursively(self, curve):
		seen = set()
		process = [ curve ]
		result = set()

		while len(process) > 0:
			nextcurve = process.pop()

			coeffs = (curve.a4(), curve.a6())
			if coeffs in seen:
				continue
			seen.add(coeffs)

			twist_results = self._debug_enumerate_curve_twists(curve)
			for ct in twist_results["twist"]:
				if ct.coeffs not in result:
					result.add(ct.coeffs)
			for ct in twist_results["iso"]:
				process.append(ct.curve)
		return result

	def _debug_enumerate_points(self, curve):
		k = curve.base_field().order()
		for x in range(1, k):
			P = curve.lift_x(curve.base_field()(x))
			Po = P.order()
			print("%3d %s" % (Po, P))


	def _compute_lops(self):
		P2base = self._get_e2_base_point()
		for (base, exponent) in factor(self._Et.order()):
			modulus = base ** exponent
			P2a = P2base * (self._Et.order() // modulus)
			Pt = self._Et.lift_x(self._Fp(P2a[0]) * self._problem["d"])
			yield (base, exponent, P2a, Pt)

	@classmethod
	def determine_suitable_curve(cls, bitlen, min_factors = 4):
		p = next_prime(random.randint(1 << (bitlen - 1), 1 << bitlen))
		d = cls._any_qnr(p)
		problem = { "p": int(p), "d": int(d) }
		max_smooth_bits = (bitlen // min_factors) + 8

		Fp = GF(p)
		for a in range(2, p):
			for b in range(2, p):
				try:
					curve = EllipticCurve(Fp, [ a, b ])
				except ArithmeticError:
					continue
				if not is_prime(curve.order()):
					continue
				if curve.order() == p:
					# anomaleous curve
					continue

				twist = cls._specific_twist(curve, d)
				to = twist.order()
				tofacts = list(factor(to))
				smooth = tofacts[-1][0]

				if len(tofacts) < min_factors:
					print("Only %d factors instead of %d." % (len(tofacts), min_factors))
					continue

				smooth_bits = int(smooth).bit_length()
				if smooth_bits > max_smooth_bits:
					print("%d factors, but not smooth enough (%d-bit-smooth, but %d-bit smoothness required)." % (len(tofacts), smooth_bits, max_smooth_bits))
					continue

				problem.update({
					"a": int(curve.a4()),
					"b": int(curve.a6()),
					"ahat": int(twist.a4()),
					"bhat": int(twist.a6()),
				})
				break
			if "a" in problem:
				break

		problem["secret"] = random.randint(1, curve.order() - 1)
		print(json.dumps(problem, indent = 4, sort_keys = True))

	def _run_lop(self, base, exponent, lop_Ep2, lop_Et):
		modulus = int(base ** exponent)
		if exponent == 1:
			print("%d [%d bit]: %-30s %s" % (base, int(lop_Et.order()).bit_length(), lop_Et, lop_Ep2))
		else:
			print("%d^%d = %d [%d bit]: %-30s %s" % (base, exponent, modulus, int(lop_Et.order()).bit_length(), lop_Et, lop_Ep2))
		x = int(lop_Ep2[0])
		pt = toyecc.AffineCurvePoint(x, int(0), self._victim_curve)
		vresponse = pt.scalar_mul_xonly(self._problem["secret"])
		print("     victim: %d -> %s" % (x, vresponse))

		if vresponse is None:
			# Point at infinity returned
			print("     point at infinity")
			print("     d mod %d = 0 (correct: %d)" % (lop_Ep2.order(), self._problem["secret"] % lop_Ep2.order()))
			self._crt_constraints[int(modulus)] = [ int(0) ]
		else:
			S = self._E2.lift_x(self._Fp2(int(vresponse)))
			if S.order() != lop_Et.order():
				print("     lift failed: wrong order %d (expected %d)" % (S.order(), lop_Et.order()))
				print("     d mod %d = 0 (correct: %d)" % (lop_Ep2.order(), self._problem["secret"] % lop_Ep2.order()))
				self._crt_constraints[int(modulus)] = [ int(0) ]
			else:
				print("     %s" % (S))
				t0 = time.time()
				dlog = lop_Ep2.discrete_log(S)
				t1 = time.time()
				print("     d mod %d = %d or %d (correct: %d)" % (lop_Ep2.order(), dlog, (-dlog % lop_Ep2.order()), self._problem["secret"] % lop_Ep2.order()))
				print("     ECDLP solved in %.1f sec for %d bit order" % (t1 - t0, int(lop_Ep2.order()).bit_length()))
				self._crt_constraints[int(modulus)] = sorted([ int(dlog), int(-dlog % lop_Ep2.order()) ])

	def _solve_crt(self):
		constraints = list(sorted(self._crt_constraints.items()))
		moduli = [ constraint[0] for constraint in constraints ]
		options = [ constraint[1] for constraint in constraints ]
		for choice in itertools.product(*options):
			crt = toyecc.CRT()
			for (modulus, value) in zip(moduli, choice):
				crt.add(value, modulus)
			guess = crt.solve()
			print("Key guess: %d" % (guess))
			if guess == self._problem["secret"]:
				print("Correct key found! %d" % (guess))
				return
		print("No correct key found :(")

	def run(self):
		self._dump_curves()
		for (base, exponent, lop_Ep2, lop_Et) in self._compute_lops():
			print()
			self._run_lop(base, exponent, lop_Ep2, lop_Et)
		print()
		self._solve_crt()


#print(InvalidPointAttack.determine_suitable_curve(bitlen = 32, min_factors = 5))
#print(InvalidPointAttack.determine_suitable_curve(bitlen = 64, min_factors = 7))
#print(InvalidPointAttack.determine_suitable_curve(bitlen = 80, min_factors = 7))

ipa = InvalidPointAttack(problem_json_filename = sys.argv[1])
ipa.run()
