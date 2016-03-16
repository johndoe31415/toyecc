#!/usr/bin/python3

p = 0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297
a = 0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF
b = 0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9

F = GF(p)
curve = EllipticCurve(F, [a,b])

# Choose two random points and make sure they're affine
P = curve.random_point()
Q = curve.random_point()
assert(P[2] == 1)
assert(Q[2] == 1)
Px = P[0]
Py = P[1]
Qx = Q[0]
Qy = Q[1]

# Add them together normally
Z = P + Q;
assert(Z[2] == 1)

# Verify the calculation by doing the math manually
x3 = (Qy-Py)^2/(Qx-Px)^2-Px-Qx
y3 = (2*Px+Qx)*(Qy-Py)/(Qx-Px)-(Qy-Py)^3/(Qx-Px)^3-Py
assert(x3 == Z[0])
assert(y3 == Z[1])

# Now twist the curve, ensure d is a QNR in F_P
d = 3
twist = EllipticCurve(F, [d^2*a, d^3*b])
assert(twist.is_quadratic_twist(curve) != 1)

# Transform P, Q and Z to the twisted curve
j = F(d).sqrt()
#j = var("j")
Pxx = d * Px
Pyy = d * j * Py
Qxx = d * Qx
Qyy = d * j * Qy
Zxx = d * Z[0]
Zyy = d * j * Z[1]

# Then perform the addition according to the addition formulas
x3 = (Qyy-Pyy)^2/(Qxx-Pxx)^2-Pxx-Qxx
y3 = (2*Pxx+Qxx)*(Qyy-Pyy)/(Qxx-Pxx)-(Qyy-Pyy)^3/(Qxx-Pxx)^3-Pyy

print(Zxx, Zyy)
print(x3, y3)
