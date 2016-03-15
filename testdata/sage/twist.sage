#!/usr/bin/python3

def play_with(q1, q2):
	print("sqrt(q1 / q2) = %s" % ((q1 / q2).sqrt()))
	print("sqrt(q2 / q1) = %s" % ((q2 / q1).sqrt()))
	for i in range(1, 10):
		print("(q1 / q2) ^ %d = 0x%x" % (i, int((q1 / q2) ** i)))
		print("(q2 / q1) ^ %d = 0x%x" % (i, int((q2 / q1) ** i)))

p = 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297
a = 0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF
b = 0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9

F = GF(p)
curve = EllipticCurve(F, [a,b])
d = F(3)
twist = curve.quadratic_twist(d)
print(curve)
# twisting parameter D > 0

(a, b) = (curve.a4(), curve.a6())
print("A   = 0x%x, B   = 0x%x" % (int(a), int(b)))

(ax, bx) = (twist.a4(), twist.a6())
print("A'  = 0x%x, B'  = 0x%x" % (int(ax), int(bx)))

has_sqrt = (kronecker(d, p) == 1)
if d == 2:
	axx = (d ** 6) * a
	bxx = (d ** 9) * b
	print("Sqrt = %s" % (d.sqrt()))
	print("A'' = 0x%x, B'' = 0x%x" % (int(axx), int(bxx)))
else:
	axx = ((4 * d) ** 2) * a
	bxx = ((4 * d) ** 3) * b
	print("Sqrt = %s" % (d.sqrt()))
	print("A'' = 0x%x, B'' = 0x%x" % (int(axx), int(bxx)))
assert(axx == ax)
assert(bxx == bx)

new_twisted_curve = EllipticCurve(F, [int(axx), int(bxx)])
assert(twist == new_twisted_curve)

print("Is quadratic twist? %s" % (twist.is_quadratic_twist(curve)))

print("="*120)

want_a = F(-3)
z = (-((want_a / a).sqrt())).sqrt()
print(z)
d = (want_a / (16 * a)).sqrt()
print("d = 0x%x" % (d))
print("Z = 0x%x" % (z))
axx = ((4 * d)**2) * a
bxx = ((4 * d)**3) * b
print("A3 = 0x%x, B3 = 0x%x" % (int(axx), int(bxx)))
assert(axx == 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294)
assert(bxx == 0x13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79)

new_twisted_curve = EllipticCurve(F, [int(axx), int(bxx)])
print("Is quadratic twist? %s" % (new_twisted_curve.is_quadratic_twist(curve)))
print("Is quatrtic twist? %s" % (new_twisted_curve.is_quartic_twist(curve)))

expect_z = F(0x1B6F5CC8DB4DC7AF19458A9CB80DC2295E5EB9C3732104CB)


