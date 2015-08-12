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

from .ShortWeierstrassCurve import ShortWeierstrassCurve
from .MontgomeryCurve import MontgomeryCurve
from .TwistedEdwardsCurve import TwistedEdwardsCurve
from .Singleton import singleton
from .FieldElement import FieldElement

@singleton
class CurveDB(object):
	def __init__(self):
		self._curves = { }
		self._lazycurves = { }
		self._taken_names = set()
		self._curvenames = set()

	@staticmethod
	def get_aliases(curve, custom_aliases = None):
		if not curve.hasname:
			raise Exception("Cannot register an unnamed curve in the curve DB")
		aliases = set()
		aliases.add(curve.name)
		aliases.add(curve.name.lower())
		if custom_aliases is not None:
			aliases |= set(custom_aliases)
		return aliases

	def _checknames(self, curvenames):		
		if len(curvenames & self._taken_names) > 0:
			taken_names = ", ".join(sorted(list(curvenames & self._taken_names)))
			raise Exception("Curve(s) named %s already registered in curve DB." % (taken_names))

	def _do_register(self, curve, curvedict, **kwargs):
		"""Actually registers the curve with all its aliases in the given
		dictionary."""
		curvenames = self.get_aliases(curve, kwargs.get("aliases"))
		self._checknames(curvenames)
		self._curvenames.add(curve.name)
		self._taken_names |= curvenames
		for curvename in curvenames:
			curvedict[curvename] = curve

	def register_lazy(self, lazycurve, **kwargs):
		"""Do a lazy registering of a curve. This means that only a curve
		surrogate is stored in the curve db and the curve is only created when
		it is requested."""
		self._do_register(lazycurve, self._lazycurves, **kwargs)

	def register(self, curve, **kwargs):
		"""Registers a curve in the curve database."""
		self._do_register(lazycurve, self._curves, **kwargs)

	def curvenames(self):
		"""Returns the names of all curves in the DB."""
		return iter(self._curvenames)

	@staticmethod
	def print_db_entry(curve):
		curveclass = curve.__class__.__name__
		params = [ ]
		params.append(("name", curve.name))
		if curveclass in [ "ShortWeierstrassCurve", "MontgomeryCurve" ]:
			params.append(("a", curve.a))
			params.append(("b", curve.b))
		elif curveclass == "TwistedEdwardsCurve":
			params.append(("a", curve.a))
			params.append(("d", curve.d))
		else:
			raise Exception(NotImplemented)			
		params.append(("p", curve.p))
		params.append(("n", curve.n))
		params.append(("h", curve.h))
		params.append(("Gx", curve.G.x))
		params.append(("Gy", curve.G.y))
	
		# Determine formatting width
		bitlen = max(curve.p.bit_length(), curve.n.bit_length())
		nibble_len = (bitlen + 3) // 4
		hexfieldlen = nibble_len + 2

		print("cdb.register_lazy(_LazyCurve(%s," % (curveclass))
		for (key, value) in params:
			if isinstance(value, str):
				valuestr = "\"%s\""% (value)
			elif isinstance(value, int) or isinstance(value, FieldElement):
				if isinstance(value, FieldElement):
					value = value.sigint()
				if value <= 1000000000:
					valuestr = "%d" % (value)
				else:
					valuestr = "%#*x" % (hexfieldlen, value)
			else:
				valuestr = "?"
			print("	%-2s = %s," % (key, valuestr))
		print("))")
		print()

	def dumpall(self):
		"""Dumps the whole curve database."""
		for curve in self:
			self.print_db_entry(curve)

	def __iter__(self):
		return iter(self[name] for name in self.curvenames())

	def __getitem__(self, name):
		"""Returns a specific curve by its name."""
		if name not in self._curves:
			if name not in self._lazycurves:
				raise KeyError("Curve named '%s' is not known in curve database." % (name))
			else:
				# Now instanciate curve
				curve = self._lazycurves[name]()

				# And cache it for the next call
				self._curves[name] = curve
		return self._curves[name]

	def __str__(self):
		return "CurveDB<%d curves, %d active>" % (len(self._curvenames), len(self._curves))


class _LazyCurve(object):
	def __init__(self, curveclass, *args, **kwargs):
		self._curveclass = curveclass
		self._args = args
		self._kwargs = kwargs

	@property
	def hasname(self):
		return self._kwargs["name"] is not None

	@property
	def name(self):
		return self._kwargs["name"]

	def __call__(self):
		return self._curveclass(*self._args, **self._kwargs)


cdb = CurveDB()
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP160r1",
	a  = 0x340e7be2a280eb74e2be61bada745d97e8f7c300,
	b  = 0x1e589a8595423412134faa2dbdec95c8d8675e58,
	p  = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620f,
	n  = 0xe95e4a5f737059dc60df5991d45029409e60fc09,
	h  = 1,
	Gx = 0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3,
	Gy = 0x1667cb477a1a8ec338f94741669c976316da6321,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP160t1",
	a  = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620c,
	b  = 0x7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380,
	p  = 0xe95e4a5f737059dc60dfc7ad95b3d8139515620f,
	n  = 0xe95e4a5f737059dc60df5991d45029409e60fc09,
	h  = 1,
	Gx = 0xb199b13b9b34efc1397e64baeb05acc265ff2378,
	Gy = 0xadd6718b7c7c1961f0991b842443772152c9e0ad,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP192r1",
	a  = 0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef,
	b  = 0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9,
	p  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297,
	n  = 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1,
	h  = 1,
	Gx = 0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6,
	Gy = 0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP192t1",
	a  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86294,
	b  = 0x13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79,
	p  = 0xc302f41d932a36cda7a3463093d18db78fce476de1a86297,
	n  = 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1,
	h  = 1,
	Gx = 0x3ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129,
	Gy = 0x97e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP224r1",
	a  = 0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43,
	b  = 0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b,
	p  = 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff,
	n  = 0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f,
	h  = 1,
	Gx = 0xd9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d,
	Gy = 0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP224t1",
	a  = 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc,
	b  = 0x4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d,
	p  = 0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff,
	n  = 0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f,
	h  = 1,
	Gx = 0x6ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d580,
	Gy = 0x374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP256r1",
	a  = 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9,
	b  = 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6,
	p  = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
	n  = 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
	h  = 1,
	Gx = 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262,
	Gy = 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP256t1",
	a  = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374,
	b  = 0x662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04,
	p  = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
	n  = 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
	h  = 1,
	Gx = 0xa3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4,
	Gy = 0x2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP320r1",
	a  = 0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4,
	b  = 0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6,
	p  = 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27,
	n  = 0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311,
	h  = 1,
	Gx = 0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611,
	Gy = 0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP320t1",
	a  = 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24,
	b  = 0xa7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353,
	p  = 0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27,
	n  = 0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311,
	h  = 1,
	Gx = 0x925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed52,
	Gy = 0x63ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP384r1",
	a  = 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826,
	b  = 0x4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11,
	p  = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53,
	n  = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565,
	h  = 1,
	Gx = 0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e,
	Gy = 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP384t1",
	a  = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50,
	b  = 0x7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee,
	p  = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53,
	n  = 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565,
	h  = 1,
	Gx = 0x18de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc,
	Gy = 0x25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP512r1",
	a  = 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca,
	b  = 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723,
	p  = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3,
	n  = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069,
	h  = 1,
	Gx = 0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822,
	Gy = 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "brainpoolP512t1",
	a  = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0,
	b  = 0x7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e,
	p  = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3,
	n  = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069,
	h  = 1,
	Gx = 0x640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da,
	Gy = 0x5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime192v1",
	a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffc,
	b  = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
	p  = 0xfffffffffffffffffffffffffffffffeffffffffffffffff,
	n  = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
	h  = 1,
	Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
	Gy = 0x7192b95ffc8da78631011ed6b24cdd573f977a11e794811,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime192v2",
	a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffc,
	b  = 0xcc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953,
	p  = 0xfffffffffffffffffffffffffffffffeffffffffffffffff,
	n  = 0xfffffffffffffffffffffffe5fb1a724dc80418648d8dd31,
	h  = 1,
	Gx = 0xeea2bae7e1497842f2de7769cfe9c989c072ad696f48034a,
	Gy = 0x6574d11d69b6ec7a672bb82a083df2f2b0847de970b2de15,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime192v3",
	a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffc,
	b  = 0x22123dc2395a05caa7423daeccc94760a7d462256bd56916,
	p  = 0xfffffffffffffffffffffffffffffffeffffffffffffffff,
	n  = 0xffffffffffffffffffffffff7a62d031c83f4294f640ec13,
	h  = 1,
	Gx = 0x7d29778100c65a1da1783716588dce2b8b4aee8e228f1896,
	Gy = 0x38a90f22637337334b49dcb66a6dc8f9978aca7648a943b0,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime239v1",
	a  = 0x7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc,
	b  = 0x6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a,
	p  = 0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff,
	n  = 0x7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b,
	h  = 1,
	Gx = 0xffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf,
	Gy = 0x7debe8e4e90a5dae6e4054ca530ba04654b36818ce226b39fccb7b02f1ae,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime239v2",
	a  = 0x7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc,
	b  = 0x617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c,
	p  = 0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff,
	n  = 0x7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063,
	h  = 1,
	Gx = 0x38af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7,
	Gy = 0x5b0125e4dbea0ec7206da0fc01d9b081329fb555de6ef460237dff8be4ba,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime239v3",
	a  = 0x7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc,
	b  = 0x255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e,
	p  = 0x7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff,
	n  = 0x7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551,
	h  = 1,
	Gx = 0x6768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a,
	Gy = 0x1607e6898f390c06bc1d552bad226f3b6fcfe48b6e818499af18e3ed6cf3,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "prime256v1",
	a  = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
	b  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
	p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
	n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
	h  = 1,
	Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
	Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp112r1",
	a  = 0xdb7c2abf62e35e668076bead2088,
	b  = 0x659ef8ba043916eede8911702b22,
	p  = 0xdb7c2abf62e35e668076bead208b,
	n  = 0xdb7c2abf62e35e7628dfac6561c5,
	h  = 1,
	Gx = 0x9487239995a5ee76b55f9c2f098,
	Gy = 0xa89ce5af8724c0a23e0e0ff77500,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp112r2",
	a  = 0x6127c24c05f38a0aaaf65c0ef02c,
	b  = 0x51def1815db5ed74fcc34c85d709,
	p  = 0xdb7c2abf62e35e668076bead208b,
	n  = 0x36df0aafd8b8d7597ca10520d04b,
	h  = 4,
	Gx = 0x4ba30ab5e892b4e1649dd0928643,
	Gy = 0xadcd46f5882e3747def36e956e97,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp128r1",
	a  = 0xfffffffdfffffffffffffffffffffffc,
	b  = 0xe87579c11079f43dd824993c2cee5ed3,
	p  = 0xfffffffdffffffffffffffffffffffff,
	n  = 0xfffffffe0000000075a30d1b9038a115,
	h  = 1,
	Gx = 0x161ff7528b899b2d0c28607ca52c5b86,
	Gy = 0xcf5ac8395bafeb13c02da292dded7a83,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp128r2",
	a  = 0xd6031998d1b3bbfebf59cc9bbff9aee1,
	b  = 0x5eeefca380d02919dc2c6558bb6d8a5d,
	p  = 0xfffffffdffffffffffffffffffffffff,
	n  = 0x3fffffff7fffffffbe0024720613b5a3,
	h  = 4,
	Gx = 0x7b6aa5d85e572983e6fb32a7cdebc140,
	Gy = 0x27b6916a894d3aee7106fe805fc34b44,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp160k1",
	a  = 0,
	b  = 7,
	p  = 0x0fffffffffffffffffffffffffffffffeffffac73,
	n  = 0x100000000000000000001b8fa16dfab9aca16b6b3,
	h  = 1,
	Gx = 0x03b4c382ce37aa192a4019e763036f4f5dd4d7ebb,
	Gy = 0x0938cf935318fdced6bc28286531733c3f03c4fee,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp160r1",
	a  = 0x0ffffffffffffffffffffffffffffffff7ffffffc,
	b  = 0x01c97befc54bd7a8b65acf89f81d4d4adc565fa45,
	p  = 0x0ffffffffffffffffffffffffffffffff7fffffff,
	n  = 0x100000000000000000001f4c8f927aed3ca752257,
	h  = 1,
	Gx = 0x04a96b5688ef573284664698968c38bb913cbfc82,
	Gy = 0x023a628553168947d59dcc912042351377ac5fb32,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp160r2",
	a  = 0x0fffffffffffffffffffffffffffffffeffffac70,
	b  = 0x0b4e134d3fb59eb8bab57274904664d5af50388ba,
	p  = 0x0fffffffffffffffffffffffffffffffeffffac73,
	n  = 0x100000000000000000000351ee786a818f3a1a16b,
	h  = 1,
	Gx = 0x052dcb034293a117e1f4ff11b30f7199d3144ce6d,
	Gy = 0x0feaffef2e331f296e071fa0df9982cfea7d43f2e,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp192k1",
	a  = 0,
	b  = 3,
	p  = 0xfffffffffffffffffffffffffffffffffffffffeffffee37,
	n  = 0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d,
	h  = 1,
	Gx = 0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d,
	Gy = 0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp224k1",
	a  = 0,
	b  = 5,
	p  = 0x0fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d,
	n  = 0x10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7,
	h  = 1,
	Gx = 0x0a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c,
	Gy = 0x07e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp224r1",
	a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe,
	b  = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
	p  = 0xffffffffffffffffffffffffffffffff000000000000000000000001,
	n  = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
	h  = 1,
	Gx = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
	Gy = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp256k1",
	a  = 0,
	b  = 7,
	p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
	n  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
	h  = 1,
	Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
	Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp384r1",
	a  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
	b  = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
	p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
	n  = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
	h  = 1,
	Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
	Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "secp521r1",
	a  = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
	b  = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
	p  = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
	n  = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
	h  = 1,
	Gx = 0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
	Gy = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "wap-wsg-idm-ecid-wtls12",
	a  = 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe,
	b  = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
	p  = 0xffffffffffffffffffffffffffffffff000000000000000000000001,
	n  = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
	h  = 1,
	Gx = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
	Gy = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "wap-wsg-idm-ecid-wtls6",
	a  = 0xdb7c2abf62e35e668076bead2088,
	b  = 0x659ef8ba043916eede8911702b22,
	p  = 0xdb7c2abf62e35e668076bead208b,
	n  = 0xdb7c2abf62e35e7628dfac6561c5,
	h  = 1,
	Gx = 0x9487239995a5ee76b55f9c2f098,
	Gy = 0xa89ce5af8724c0a23e0e0ff77500,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "wap-wsg-idm-ecid-wtls7",
	a  = 0x0fffffffffffffffffffffffffffffffeffffac70,
	b  = 0x0b4e134d3fb59eb8bab57274904664d5af50388ba,
	p  = 0x0fffffffffffffffffffffffffffffffeffffac73,
	n  = 0x100000000000000000000351ee786a818f3a1a16b,
	h  = 1,
	Gx = 0x052dcb034293a117e1f4ff11b30f7199d3144ce6d,
	Gy = 0x0feaffef2e331f296e071fa0df9982cfea7d43f2e,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "wap-wsg-idm-ecid-wtls8",
	a  = 0,
	b  = 3,
	p  = 0x0fffffffffffffffffffffffffde7,
	n  = 0x100000000000001ecea551ad837e9,
	h  = 1,
	Gx = 1,
	Gy = 2,
))

cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "wap-wsg-idm-ecid-wtls9",
	a  = 0,
	b  = 3,
	p  = 0x0fffffffffffffffffffffffffffffffffffc808f,
	n  = 0x100000000000000000001cdc98ae0e2de574abf33,
	h  = 1,
	Gx = 1,
	Gy = 2,
))

cdb.register_lazy(_LazyCurve(MontgomeryCurve,
	name = "curve25519",
	a  = 486662,
	b  = 1,
	p  = (2 ** 255) - 19,
	n  = (2 ** 252) + 27742317777372353535851937790883648493,
	h  = 8,
	Gx = 0x9,
	Gy = 0x5f51e65e475f794b1fe122d388b72eb36dc2b28192839e4dd6163a5d81312c14,	
))

cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "ed25519",
	a  = -1,
	d  = 37095705934669439343138083508754565189542113879843219016388785533085940283555,
	p  = (2 ** 255) - 19,
	n  = (2 ** 252) + 27742317777372353535851937790883648493,
	h  = 8,
	Gx = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a,
	Gy = 0x6666666666666666666666666666666666666666666666666666666666666658,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "Anomalous",
	a  = 0x98d0fac687d6343eb1a1f595283eb1a1f58d0fac687d635f5e4,
	b  = 0x4a1f58d0fac687d6343eb1a5e2d6343eb1a1f58d0fac688ab3f,
	p  = 0xb0000000000000000000000953000000000000000000001f9d7,
	n  = 0xb0000000000000000000000953000000000000000000001f9d7,
	h  = 1,
	Gx = 0x101efb35fd1963c4871a2d17edaafa7e249807f58f8705126c6,
	Gy = 0x22389a3954375834304ba1d509a97de6c07148ea7f5951b20e7,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(MontgomeryCurve,
	name = "M-221",
	a  = 117050,
	b  = 1,
	p  = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffd,
	n  =  0x40000000000000000000000000015a08ed730e8a2f77f005042605b,
	h  = 8,
	Gx = 4,
	Gy =  0xf7acdd2a4939571d1cef14eca37c228e61dbff10707dc6c08c5056d,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "E-222",
	a  = 1,
	d  = 160102,
	p  = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffff8b,
	n  =  0xffffffffffffffffffffffffffff70cbc95e932f802f31423598cbf,
	h  = 4,
	Gx = 0x19b12bb156a389e55c9768c303316d07c23adab3736eb2bc3eb54e51,
	Gy = 28,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "NIST P-224",
	a  = -3,
	b  = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
	p  = 0xffffffffffffffffffffffffffffffff000000000000000000000001,
	n  = 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
	h  = 1,
	Gx = 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
	Gy = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "Curve1174",
	a  = 1,
	d  = -1174,
	p  = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7,
	n  = 0x1fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971,
	h  = 4,
	Gx = 0x37fbb0cea308c479343aee7c029a190c021d96a492ecd6516123f27bce29eda,
	Gy = 0x6b72f82d47fb7cc6656841169840e0c4fe2dee2af3f976ba4ccb1bf9b46360e,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "BN(2,254)",
	a  = 0,
	b  = 2,
	p  = 0x2523648240000001ba344d80000000086121000000000013a700000000000013,
	n  = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d,
	h  = 1,
	Gx = -1,
	Gy = 1,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "ANSSI FRP256v1",
	a  = -3,
	b  = 0xee353fca5428a9300d4aba754a44c00fdfec0c9ae4b1a1803075ed967b7bb73f,
	p  = 0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03,
	n  = 0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1,
	h  = 1,
	Gx = 0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff,
	Gy = 0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "NIST P-256",
	a  = -3,
	b  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
	p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
	n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
	h  = 1,
	Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
	Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "E-382",
	a  = 1,
	d  = -67254,
	p  = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97,
	n  =  0xfffffffffffffffffffffffffffffffffffffffffffffffd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719,
	h  = 4,
	Gx = 0x196f8dd0eab20391e5f05be96e8d20ae68f840032b0b64352923bab85364841193517dbce8105398ebc0cc9470f79603,
	Gy = 17,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(MontgomeryCurve,
	name = "M-383",
	a  = 2065150,
	b  = 1,
	p  = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45,
	n  = 0x10000000000000000000000000000000000000000000000006c79673ac36ba6e7a32576f7b1b249e46bbc225be9071d7,
	h  = 8,
	Gx = 12,
	Gy = 0x1ec7ed04aaf834af310e304b2da0f328e7c165f0e8988abd3992861290f617aa1f1b2e7d0b6e332e969991b62555e77e,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(MontgomeryCurve,
	name = "Curve383187",
	a  = 229969,
	b  = 1,
	p  = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45,
	n  = 0x1000000000000000000000000000000000000000000000000e85a85287a1488acd41ae84b2b7030446f72088b00a0e21,
	h  = 8,
	Gx = 5,
	Gy = 0x1eebe07dc1871896732b12d5504a32370471965c7a11f2c89865f855ab3cbd7c224e3620c31af3370788457dd5ce46df,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(ShortWeierstrassCurve,
	name = "NIST P-384",
	a  = -3,
	b  = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
	p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
	n  = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
	h  = 1,
	Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
	Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "Curve41417",
	a  = 1,
	d  = 3617,
	p  = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef,
	n  =  0x7ffffffffffffffffffffffffffffffffffffffffffffffffffeb3cc92414cf706022b36f1c0338ad63cf181b0e71a5e106af79,
	h  = 8,
	Gx = 0x1a334905141443300218c0631c326e5fcd46369f44c03ec7f57ff35498a4ab4d6d6ba111301a73faa8537c64c4fd3812f3cbc595,
	Gy = 34,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "Ed448-Goldilocks",
	a  = 1,
	d  = -39081,
	p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
	n  = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3,
	h  = 4,
	Gx = 0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf3932d94c63d96c170033f4ba0c7f0de840aed939f,
	Gy = 19,
), aliases = [ "Ed448" ])

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(MontgomeryCurve,
	name = "M-511",
	a  = 530438,
	b  = 1,
	p  = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45,
	n  = 0x100000000000000000000000000000000000000000000000000000000000000017b5feff30c7f5677ab2aeebd13779a2ac125042a6aa10bfa54c15bab76baf1b,
	h  = 8,
	Gx = 5,
	Gy = 0x2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5,
))

# Curve imported from SafeCurves http://safecurves.cr.yp.to
cdb.register_lazy(_LazyCurve(TwistedEdwardsCurve,
	name = "E-521",
	a  = 1,
	d  = -376014,
	p  = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
	n  =  0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b,
	h  = 4,
	Gx =  0x752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c,
	Gy = 12,
))

def getcurvedb():
	"""Returns an instance of the curve database singleton object."""
	return CurveDB()

def getcurvenames():
	"""Returns the names of all curves known to joeecc."""
	return CurveDB().curvenames()

def getcurvebyname(name):
	"""Returns a curve by its name."""
	return CurveDB()[name]

