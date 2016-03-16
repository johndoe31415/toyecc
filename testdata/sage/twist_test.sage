#!/usr/bin/python3
#
# ShortWeierstrassCurve<brainpoolP160r1>
curve_p = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620f
curve_F = GF(curve_p)
curve_a = 0x340e7be2a280eb74e2be61bada745d97e8f7c300
curve_b = 0x1e589a8595423412134faa2dbdec95c8d8675e58
curve = EllipticCurve(curve_F, [ curve_a, curve_b ])

# ShortWeierstrassCurve<brainpoolP160t1>
twist_p = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620f
twist_F = GF(twist_p)
twist_a = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620c
twist_b = 0x7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380
twist = EllipticCurve(twist_F, [ twist_a, twist_b ])


# ShortWeierstrassCurve<y^2 = x^3 + 0x9 x + 0x69bb5b0c0d7cfef2d0f91f76858400f911ddf8df mod 0xe95e4a5f737059dc60dfc7ad95b3d8139515620f>
iso_p = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620f
iso_F = GF(iso_p)
iso_a = 0x9
iso_b = 0x69bb5b0c0d7cfef2d0f91f76858400f911ddf8df
iso = EllipticCurve(iso_F, [ iso_a, iso_b ])

print("-"*120)
print(curve.is_quadratic_twist(twist))
print(curve.is_quadratic_twist(iso))
print(twist.is_quadratic_twist(iso))

twist_me = curve
for i in range(10):
	print(i, twist_me)
	twist_me = twist_me.quadratic_twist()
