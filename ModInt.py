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
import math
import timeit
import random

from Comparable import Comparable

class ModInt(Comparable):
	def __init__(self, intvalue, modulus):
		assert(isinstance(intvalue, int))
		assert(isinstance(modulus, int))
		self._intvalue = intvalue % modulus
		self._modulus = modulus
		self._rootable = (self._modulus % 4) == 3

	def clone(self):
		return ModInt(self._intvalue, self._modulus)

	def getintvalue(self):
		return self._intvalue

	def getmodulus(self):
		return self._modulus
	
	def setmodulus(self, modulus):
		assert(isinstance(modulus, int))
		self._modulus = modulus

	def _ioperation(self, value, operation):
		if isinstance(value, int):
			self._intvalue = (operation(self._intvalue, value)) % self._modulus
		elif isinstance(value, ModInt):
			assert(self._modulus == value._modulus)
			self._intvalue = operation(self._intvalue, value._intvalue) % self._modulus
		else:
			raise TypeError("Unsupported type %s." % (str(type(value))))
		return self

	def _eea(a, b):
		assert(isinstance(a, int))
		assert(isinstance(b, int))
		(s, t, u, v) = (1, 0, 0, 1)
		while b != 0:
			(q, r) = (a // b, a % b)
			(uneu, vneu) = (s, t)
			s = u - (q * s)
			t = v - (q * t)
			(a, b) = (b, r)
			(u, v) = (uneu, vneu)
		return (a, u, v)

	def _intdiv(self, a, b):
		if b == 0:
			raise Exception("Division by zero")
		(ggt, u, v) = ModInt._eea(b, self._modulus)
		inverse = (v % self._modulus)
		return (a * inverse)

	def __iadd__(self, value):
		return self._ioperation(value, lambda a, b: a + b)
	
	def __isub__(self, value):
		return self._ioperation(value, lambda a, b: a - b)
	
	def __imul__(self, value):
		return self._ioperation(value, lambda a, b: a * b)
	
	def __ipow__(self, exponent):
		assert(isinstance(exponent, int))
		assert(exponent >= 0)

		if exponent < 1000:
			# Use simple exponentiation for small exponents
			return self._ioperation(exponent, lambda a, b: a ** b)
		
		# For large exponents, use square-and-multiply
		bitcount = math.ceil(math.log(exponent, 2)) + 1
		n = self.clone()
		self._intvalue = 1
		for bit in range(bitcount):
			if (exponent & (1 << bit)):
				self *= n
			n *= n
		return self


	def __ifloordiv__(self, value):
		return self._ioperation(value, self._intdiv)

	def __add__(self, value):
		n = self.clone()
		n += value
		return n

	def __radd__(self, value):
		return self + value

	def __sub__(self, value):
		n = self.clone()
		n -= value
		return n
	
	def __mul__(self, value):
		n = self.clone()
		n *= value
		return n
	
	def __rmul__(self, value):
		return self * value
	
	def __floordiv__(self, value):
		n = self.clone()
		n //= value
		return n
	
	def __pow__(self, value):
		n = self.clone()
		n **= value
		return n
	
	def __neg__(self):
		n = self.clone()
		n._intvalue = -n._intvalue % self._modulus
		return n

	def sqrt(self):
		assert(self._rootable)
		posroot = self ** ((self._modulus + 1) // 4)
		if (posroot * posroot) == self:			
			negroot = -posroot
			return (posroot, negroot)
		else:
			# No square root for this value
			return None

	def inverse(self):
		if self._intvalue == 0:
			raise Exception("Trying to invert zero")
		(ggt, u, v) = ModInt._eea(self._intvalue, self._modulus)
		inverse = (v % self._modulus)
		return inverse		

	def cmpkey(self):
		return (self._modulus, self._intvalue)

	def __str__(self):
		return str(self._intvalue)

if __name__ == "__main__":
	a = ModInt(15, 23)
	b = ModInt(20, 23)
	assert(a + b == ModInt(12, 23))
	assert(b + a == ModInt(12, 23))
	assert(a + b - b == a)
	assert(b + a - a == b)
	
	assert(a - b == ModInt(18, 23))
	assert(a - b + b == a)
	assert(b - a + a == b)

	assert(a * b == ModInt(1, 23))
	assert(b * a == ModInt(1, 23))
	assert(a * b // b == a)
	assert(b * a // a == b)

	assert(a // b == ModInt(18, 23))
	assert(a // b * b == a)
	assert(b // a * a == b)

	assert((ModInt(2, 101) ** 473289743783748378).getintvalue() == 21)
	assert((ModInt(3, 101) ** 473289743783748378).getintvalue() == 33)
	assert((ModInt(4, 101) ** 473289743783748378).getintvalue() == 37)
	assert((ModInt(5, 101) ** 473289743783748378).getintvalue() == 24)

	x = ModInt(1000, 2003)
	s = x.sqrt()
	assert(s)
	(s1, s2) = s
	assert(s1 * s1 == x)
	assert(s2 * s2 == x)

	assert((ModInt(19, 23) ** 5).getintvalue() == 11)
	assert((ModInt(19, 23) ** 12).getintvalue() == 4)
	assert((ModInt(14, 23) ** 20).getintvalue() == 2)
	assert((ModInt(1, 23) ** 19).getintvalue() == 1)
	assert((ModInt(18, 23) ** 17).getintvalue() == 8)
	assert((ModInt(18, 23) ** 20).getintvalue() == 12)
	assert((ModInt(18, 23) ** 17).getintvalue() == 8)
	assert((ModInt(20, 23) ** 12).getintvalue() == 3)
	assert((ModInt(3, 23) ** 17).getintvalue() == 16)
	assert((ModInt(14, 23) ** 3).getintvalue() == 7)
	assert((ModInt(4, 23) ** 4).getintvalue() == 3)
	assert((ModInt(10, 23) ** 4).getintvalue() == 18)
	assert((ModInt(18, 23) ** 2).getintvalue() == 2)
	assert((ModInt(10, 23) ** 17).getintvalue() == 17)
	assert((ModInt(3, 23) ** 9).getintvalue() == 18)
	assert((ModInt(6, 23) ** 10).getintvalue() == 4)
	assert((ModInt(22, 23) + 3).getintvalue() == 2)
	assert((ModInt(16, 23) + 16).getintvalue() == 9)
	assert((ModInt(22, 23) + 10).getintvalue() == 9)
	assert((ModInt(6, 23) + 22).getintvalue() == 5)
	assert((ModInt(6, 23) + 13).getintvalue() == 19)
	assert((ModInt(20, 23) + 17).getintvalue() == 14)
	assert((ModInt(3, 23) + 2).getintvalue() == 5)
	assert((ModInt(6, 23) + 21).getintvalue() == 4)
	assert((ModInt(16, 23) + 6).getintvalue() == 22)
	assert((ModInt(5, 23) + 6).getintvalue() == 11)
	assert((ModInt(9, 23) + 10).getintvalue() == 19)
	assert((ModInt(18, 23) + 17).getintvalue() == 12)
	assert((ModInt(2, 23) + 15).getintvalue() == 17)
	assert((ModInt(14, 23) + 21).getintvalue() == 12)
	assert((ModInt(15, 23) + 2).getintvalue() == 17)
	assert((ModInt(20, 23) + 20).getintvalue() == 17)
	assert((ModInt(1, 23) - 3).getintvalue() == 21)
	assert((ModInt(12, 23) - 9).getintvalue() == 3)
	assert((ModInt(19, 23) - 3).getintvalue() == 16)
	assert((ModInt(8, 23) - 10).getintvalue() == 21)
	assert((ModInt(4, 23) - 9).getintvalue() == 18)
	assert((ModInt(21, 23) - 20).getintvalue() == 1)
	assert((ModInt(17, 23) - 17).getintvalue() == 0)
	assert((ModInt(8, 23) - 17).getintvalue() == 14)
	assert((ModInt(18, 23) - 9).getintvalue() == 9)
	assert((ModInt(15, 23) - 18).getintvalue() == 20)
	assert((ModInt(7, 23) - 5).getintvalue() == 2)
	assert((ModInt(14, 23) - 21).getintvalue() == 16)
	assert((ModInt(1, 23) - 5).getintvalue() == 19)
	assert((ModInt(13, 23) - 3).getintvalue() == 10)
	assert((ModInt(2, 23) - 1).getintvalue() == 1)
	assert((ModInt(13, 23) - 15).getintvalue() == 21)
	assert((ModInt(13, 23) // 16).getintvalue() == 8)
	assert((ModInt(14, 23) // 8).getintvalue() == 19)
	assert((ModInt(2, 23) // 17).getintvalue() == 15)
	assert((ModInt(0, 23) // 5).getintvalue() == 0)
	assert((ModInt(9, 23) // 6).getintvalue() == 13)
	assert((ModInt(14, 23) // 17).getintvalue() == 13)
	assert((ModInt(1, 23) // 11).getintvalue() == 21)
	assert((ModInt(14, 23) // 9).getintvalue() == 22)
	assert((ModInt(9, 23) // 16).getintvalue() == 2)
	assert((ModInt(1, 23) // 12).getintvalue() == 2)
	assert((ModInt(13, 23) // 21).getintvalue() == 5)
	assert((ModInt(15, 23) // 19).getintvalue() == 2)
	assert((ModInt(5, 23) // 5).getintvalue() == 1)
	assert((ModInt(8, 23) // 6).getintvalue() == 9)
	assert((ModInt(19, 23) // 8).getintvalue() == 11)
	assert((ModInt(4, 23) // 10).getintvalue() == 5)
	assert((ModInt(3, 101) ** 46).getintvalue() == 96)
	assert((ModInt(17, 101) ** 89).getintvalue() == 6)
	assert((ModInt(83, 101) ** 97).getintvalue() == 35)
	assert((ModInt(64, 101) ** 30).getintvalue() == 84)
	assert((ModInt(61, 101) ** 56).getintvalue() == 56)
	assert((ModInt(61, 101) ** 9).getintvalue() == 15)
	assert((ModInt(39, 101) ** 28).getintvalue() == 84)
	assert((ModInt(40, 101) ** 32).getintvalue() == 79)
	assert((ModInt(69, 101) ** 98).getintvalue() == 65)
	assert((ModInt(74, 101) ** 56).getintvalue() == 58)
	assert((ModInt(73, 101) ** 0).getintvalue() == 1)
	assert((ModInt(8, 101) ** 86).getintvalue() == 47)
	assert((ModInt(56, 101) ** 92).getintvalue() == 16)
	assert((ModInt(60, 101) ** 25).getintvalue() == 91)
	assert((ModInt(86, 101) ** 84).getintvalue() == 56)
	assert((ModInt(94, 101) ** 11).getintvalue() == 50)
	assert((ModInt(91, 101) + 52).getintvalue() == 42)
	assert((ModInt(75, 101) + 79).getintvalue() == 53)
	assert((ModInt(42, 101) + 43).getintvalue() == 85)
	assert((ModInt(75, 101) + 82).getintvalue() == 56)
	assert((ModInt(99, 101) + 63).getintvalue() == 61)
	assert((ModInt(10, 101) + 49).getintvalue() == 59)
	assert((ModInt(8, 101) + 49).getintvalue() == 57)
	assert((ModInt(74, 101) + 81).getintvalue() == 54)
	assert((ModInt(53, 101) + 19).getintvalue() == 72)
	assert((ModInt(51, 101) + 65).getintvalue() == 15)
	assert((ModInt(80, 101) + 56).getintvalue() == 35)
	assert((ModInt(55, 101) + 61).getintvalue() == 15)
	assert((ModInt(53, 101) + 80).getintvalue() == 32)
	assert((ModInt(58, 101) + 2).getintvalue() == 60)
	assert((ModInt(96, 101) + 74).getintvalue() == 69)
	assert((ModInt(83, 101) + 93).getintvalue() == 75)
	assert((ModInt(17, 101) - 27).getintvalue() == 91)
	assert((ModInt(34, 101) - 1).getintvalue() == 33)
	assert((ModInt(63, 101) - 23).getintvalue() == 40)
	assert((ModInt(74, 101) - 76).getintvalue() == 99)
	assert((ModInt(64, 101) - 65).getintvalue() == 100)
	assert((ModInt(29, 101) - 25).getintvalue() == 4)
	assert((ModInt(0, 101) - 69).getintvalue() == 32)
	assert((ModInt(23, 101) - 40).getintvalue() == 84)
	assert((ModInt(23, 101) - 46).getintvalue() == 78)
	assert((ModInt(31, 101) - 67).getintvalue() == 65)
	assert((ModInt(17, 101) - 100).getintvalue() == 18)
	assert((ModInt(11, 101) - 22).getintvalue() == 90)
	assert((ModInt(26, 101) - 6).getintvalue() == 20)
	assert((ModInt(5, 101) - 21).getintvalue() == 85)
	assert((ModInt(19, 101) - 48).getintvalue() == 72)
	assert((ModInt(52, 101) - 34).getintvalue() == 18)
	assert((ModInt(70, 101) // 84).getintvalue() == 85)
	assert((ModInt(42, 101) // 92).getintvalue() == 29)
	assert((ModInt(9, 101) // 11).getintvalue() == 10)
	assert((ModInt(87, 101) // 28).getintvalue() == 50)
	assert((ModInt(99, 101) // 10).getintvalue() == 20)
	assert((ModInt(21, 101) // 89).getintvalue() == 74)
	assert((ModInt(51, 101) // 29).getintvalue() == 54)
	assert((ModInt(10, 101) // 99).getintvalue() == 96)
	assert((ModInt(2, 101) // 64).getintvalue() == 60)
	assert((ModInt(98, 101) // 79).getintvalue() == 69)
	assert((ModInt(24, 101) // 6).getintvalue() == 4)
	assert((ModInt(65, 101) // 34).getintvalue() == 94)
	assert((ModInt(54, 101) // 59).getintvalue() == 42)
	assert((ModInt(96, 101) // 55).getintvalue() == 55)
	assert((ModInt(27, 101) // 94).getintvalue() == 25)
	assert((ModInt(84, 101) // 36).getintvalue() == 36)
	assert((ModInt(45329398547330232435475204068501392759, 170141183460469231731687303715884105727) ** 23973357120524123688767677450838423404).getintvalue() == 110625867554914261405235347771839473528)
	assert((ModInt(11096317216645540333687625413300885798, 170141183460469231731687303715884105727) ** 18350067802502312484374146949394432005).getintvalue() == 158114342748150869616337867244357893527)
	assert((ModInt(105193728357093738052129993765343901393, 170141183460469231731687303715884105727) ** 28949868692861977936123607826349169475).getintvalue() == 97469690940520651844215943924110140562)
	assert((ModInt(111055120216185479216549737895719889955, 170141183460469231731687303715884105727) ** 116796601068080310567096901526856239558).getintvalue() == 143288233252562942061753559724655924484)
	assert((ModInt(118573387676321580035191294408665717202, 170141183460469231731687303715884105727) ** 118468724281467837804867816531495356951).getintvalue() == 25384169807760052976344572805881045078)
	assert((ModInt(8453841496330693524076697666656810794, 170141183460469231731687303715884105727) ** 50936640660640246195941254951084298956).getintvalue() == 89980634104306998553990016030498527717)
	assert((ModInt(3126171733569194607538752261348981043, 170141183460469231731687303715884105727) ** 89540119583121092487935700750509976672).getintvalue() == 76789997572366225883637242904225680866)
	assert((ModInt(87408682732145428292803410374197679069, 170141183460469231731687303715884105727) ** 73294773716505932813644442251790490252).getintvalue() == 30190042501166266896046398631549945852)
	assert((ModInt(133656934690862077279671066447610175665, 170141183460469231731687303715884105727) ** 167537713805753850504640915450779147113).getintvalue() == 35661701185378333693521640055115158413)
	assert((ModInt(98916010222012311006195259181587327980, 170141183460469231731687303715884105727) ** 43646275964617627585990852451242571176).getintvalue() == 113494102718163694969171327315905227995)
	assert((ModInt(63972045063721755734341771679385747085, 170141183460469231731687303715884105727) ** 54196951232327114864338986457233698387).getintvalue() == 45674328667154461933222295595156598033)
	assert((ModInt(30148817818891517113115639309493720746, 170141183460469231731687303715884105727) ** 79460949570435413221573946148779586587).getintvalue() == 44923150826036815903390792324737278379)
	assert((ModInt(14365600219786747087436337553351351653, 170141183460469231731687303715884105727) ** 112788553884177448692041938153888362529).getintvalue() == 66193098425771394236023545922584075435)
	assert((ModInt(107876445691250920950383433660235638727, 170141183460469231731687303715884105727) ** 63175031301901038638538102811208915385).getintvalue() == 43293126929407246606869088225298896601)
	assert((ModInt(656600543513838100592447618947479104, 170141183460469231731687303715884105727) ** 9316063397339917001814241291992219008).getintvalue() == 125439992161573737926617751254277143302)
	assert((ModInt(8515732054006400859632859854758105270, 170141183460469231731687303715884105727) ** 154793104050145597808664399207755838006).getintvalue() == 80169600713538798061924004526058523555)
	assert((ModInt(136632104926671259150658557204382855307, 170141183460469231731687303715884105727) + 140120717775505985648375652851614073638).getintvalue() == 106611639241708013067346906340112823218)
	assert((ModInt(38621638155689111539732260997177321764, 170141183460469231731687303715884105727) + 148910265184787996364066007383537138821).getintvalue() == 17390719880007876172110964664830354858)
	assert((ModInt(104060080608448838825399857423116490745, 170141183460469231731687303715884105727) + 15866546562265594892647176808646907722).getintvalue() == 119926627170714433718047034231763398467)
	assert((ModInt(135283065963309348867343419514142663254, 170141183460469231731687303715884105727) + 19283766952051149519051861565933157158).getintvalue() == 154566832915360498386395281080075820412)
	assert((ModInt(129120665366701743301002608695639274872, 170141183460469231731687303715884105727) + 146665354566953345487941378645052581274).getintvalue() == 105644836473185857057256683624807750419)
	assert((ModInt(30274191172009551312658490814045446047, 170141183460469231731687303715884105727) + 116086245620507866092530122516684873230).getintvalue() == 146360436792517417405188613330730319277)
	assert((ModInt(92821078054382328459521199148602253460, 170141183460469231731687303715884105727) + 21453897095620677846008191705950115569).getintvalue() == 114274975150003006305529390854552369029)
	assert((ModInt(113196838221973538581294430840107593118, 170141183460469231731687303715884105727) + 7120339564147990318433671914714064895).getintvalue() == 120317177786121528899728102754821658013)
	assert((ModInt(69114258914682490045468116259427841467, 170141183460469231731687303715884105727) + 1991712575999046718015252192095523128).getintvalue() == 71105971490681536763483368451523364595)
	assert((ModInt(109545890323014722350320179132149710664, 170141183460469231731687303715884105727) + 163857925843134909444560687945185850758).getintvalue() == 103262632705680400063193563361451455695)
	assert((ModInt(71961452646098185936710794302606932344, 170141183460469231731687303715884105727) + 123269683332847795071057959722788502465).getintvalue() == 25089952518476749276081450309511329082)
	assert((ModInt(77479169662442455854731274618943998038, 170141183460469231731687303715884105727) + 59269467271209903523116433439279610302).getintvalue() == 136748636933652359377847708058223608340)
	assert((ModInt(4000584729672543964294135190189425293, 170141183460469231731687303715884105727) + 124633593148062781483437344640225262257).getintvalue() == 128634177877735325447731479830414687550)
	assert((ModInt(44944448567903287336360285271047036054, 170141183460469231731687303715884105727) + 42934577016844380890687405816579749647).getintvalue() == 87879025584747668227047691087626785701)
	assert((ModInt(15792232760272254417367391186546298212, 170141183460469231731687303715884105727) + 92629712458496110182888116723592226146).getintvalue() == 108421945218768364600255507910138524358)
	assert((ModInt(16744519022997425945591286216498857854, 170141183460469231731687303715884105727) + 60097347038133774973283644794283514608).getintvalue() == 76841866061131200918874931010782372462)
	assert((ModInt(106152913003121313917911941285262726732, 170141183460469231731687303715884105727) - 87195086898390730358371679807644887247).getintvalue() == 18957826104730583559540261477617839485)
	assert((ModInt(45687281695846974635956411826165480656, 170141183460469231731687303715884105727) - 162213007661054927807473821400626255209).getintvalue() == 53615457495261278560169894141423331174)
	assert((ModInt(15257030762745645948491801499137632857, 170141183460469231731687303715884105727) - 7418989103289055301648335264728502394).getintvalue() == 7838041659456590646843466234409130463)
	assert((ModInt(106611804313960378162812847699836663716, 170141183460469231731687303715884105727) - 140665279939978230481300773387419903967).getintvalue() == 136087707834451379413199378028300865476)
	assert((ModInt(133838733144617943706855944584448231448, 170141183460469231731687303715884105727) - 58467537767098938120996889592931844682).getintvalue() == 75371195377519005585859054991516386766)
	assert((ModInt(95450444652509275212240754918440080423, 170141183460469231731687303715884105727) - 76033833226821264963537581552025667121).getintvalue() == 19416611425688010248703173366414413302)
	assert((ModInt(55367802431278463738034647542577651919, 170141183460469231731687303715884105727) - 18005316014316544179988151202837054857).getintvalue() == 37362486416961919558046496339740597062)
	assert((ModInt(125163033529513795858921820373190159377, 170141183460469231731687303715884105727) - 54475023212382152652298561017006898212).getintvalue() == 70688010317131643206623259356183261165)
	assert((ModInt(64661737350159901732983806959842729302, 170141183460469231731687303715884105727) - 45176078586475432784323819536299959164).getintvalue() == 19485658763684468948659987423542770138)
	assert((ModInt(107632274661578650916779608041071393978, 170141183460469231731687303715884105727) - 7589249240176203346240012712050723130).getintvalue() == 100043025421402447570539595329020670848)
	assert((ModInt(164830283351449861312560615156382133149, 170141183460469231731687303715884105727) - 38881694406333428951872876266198212847).getintvalue() == 125948588945116432360687738890183920302)
	assert((ModInt(145614266142808620579696974736201112667, 170141183460469231731687303715884105727) - 98440694630752268006876234464090231362).getintvalue() == 47173571512056352572820740272110881305)
	assert((ModInt(64490301041749803164735778256826041594, 170141183460469231731687303715884105727) - 154475020120574089642783104165898103822).getintvalue() == 80156464381644945253639977806812043499)
	assert((ModInt(115379742931322370510762640452114179672, 170141183460469231731687303715884105727) - 133011663520640094345715915522570422404).getintvalue() == 152509262871151507896734028645427862995)
	assert((ModInt(130168725802159753553417756246748506660, 170141183460469231731687303715884105727) - 123362500924770089422799946293438475643).getintvalue() == 6806224877389664130617809953310031017)
	assert((ModInt(38798461907097343442844080195939551410, 170141183460469231731687303715884105727) - 112708521425705507018391248752189820480).getintvalue() == 96231123941861068156140135159633836657)
	assert((ModInt(169635720912393385456311228029418721549, 170141183460469231731687303715884105727) // 5125980552749438842852750418916796525).getintvalue() == 107646814503452217117283843436202007165)
	assert((ModInt(107882884231390003679995023970257678803, 170141183460469231731687303715884105727) // 151763708725767129083405213066672737954).getintvalue() == 82889642741106710193739689277845192084)
	assert((ModInt(94241150083544367565611230042352711183, 170141183460469231731687303715884105727) // 75036922656613131426921476208210274563).getintvalue() == 153955148262808660845602842965393338168)
	assert((ModInt(100495636541697890794063010067874869700, 170141183460469231731687303715884105727) // 106212552742865435371691465447091858111).getintvalue() == 102733954716615225361079724718408770035)
	assert((ModInt(108839390278524717297468354520537885106, 170141183460469231731687303715884105727) // 100040281751285786749878371784622849611).getintvalue() == 9321205938575402744328233089858754436)
	assert((ModInt(117511643750848179104389378603022818870, 170141183460469231731687303715884105727) // 28480687143633577095730875558790621479).getintvalue() == 57299652569101370544286329898224085396)
	assert((ModInt(114994670019423707745148692983614490300, 170141183460469231731687303715884105727) // 58187529989294639311237210961779471414).getintvalue() == 147155163523377143250121888935297674289)
	assert((ModInt(107318671941012978233844525463904778624, 170141183460469231731687303715884105727) // 123654017802499232542387840704798462996).getintvalue() == 106439330727364375694930105937996868447)
	assert((ModInt(132944172934937854746756050726407372454, 170141183460469231731687303715884105727) // 154276342736674962621014167992354449125).getintvalue() == 27903634466374769281978778767278769694)
	assert((ModInt(25662843858972547447022692024664104224, 170141183460469231731687303715884105727) // 158748231144141156279066123094923903399).getintvalue() == 29201388396028385555406537979410867836)
	assert((ModInt(113465879405035451701821832943645298828, 170141183460469231731687303715884105727) // 120460349755642205984621606946479112366).getintvalue() == 71248519280901116320580234730652271391)
	assert((ModInt(8334941716861450887188645947309029530, 170141183460469231731687303715884105727) // 50138957532465094846999960859152732423).getintvalue() == 101160997466615734206526379505805888684)
	assert((ModInt(26920812363722003034821933852333560994, 170141183460469231731687303715884105727) // 102212722464591334411157093773616161792).getintvalue() == 25692793581031235137954843595156037418)
	assert((ModInt(134287335350600618899342739598509916590, 170141183460469231731687303715884105727) // 156617330166893666970965386415918144196).getintvalue() == 144891184299551137640458323577893882867)
	assert((ModInt(128108665602581376305705079145332638442, 170141183460469231731687303715884105727) // 151184636384337255092177528680036397052).getintvalue() == 7671040721822175495116587335138601275)
	assert((ModInt(14455986081875437153071558887236407967, 170141183460469231731687303715884105727) // 154668195530012920576141463919463625172).getintvalue() == 157598580654627146019924599576602305897)

#	def s():
#		p = (2 ** 127) - 1
#		(ModInt(12, p) ** 1000).getintvalue()
#	t = timeit.Timer(stmt = s)
#	print(t.timeit(10000))
	

	if (len(sys.argv) == 2) and (sys.argv[1] == "gentcdata"):		
		primes = [ 23, 101, (2 ** 127) - 1, (2 ** 521) - 1 ]
		numbers = [ 0, 1, 2, 3 ]
		for prime in primes:
			numbers.append(prime - 1)
		for i in range(3):
			numbers.append(random.randint(2 ** 10, 2 ** 11))
		for i in range(3):
			numbers.append(random.randint(2 ** 20, 2 ** 21))
		for i in range(3):
			numbers.append(random.randint(2 ** 128, 2 ** 129))
		for i in range(3):
			numbers.append(random.randint(2 ** 300, 2 ** 301))

		print("# Testcase data for modular integer operations")
		print("# Test data with two operands:")
		print("# Addition      : +")
		print("# Subtraction   : -")
		print("# Multiplication: *")
		print("# Division      : /")
		print("# Exponentiation: ^")
		print()
		print("# Test data with one operand:")
		print("# Inverse       : I")
		print("# Square root   : S")
		print()
		print("# All numbers in hex")
		print("# Format: Op1 [Number1] [Operation] [Number2] [Prime] [Result]")
		print("# Format: Op2 [Number1] [Operation] [Prime] [Result1] ([Result2])")
		print()
		op1 = [ ("sqrt", "S"), ("inverse", "I") ]
		op2 = [ ("+", "+"), ("-", "-"), ("*", "*"), ("//", "/"), ("**", "^") ]
		for prime in primes:
			print("# All following data is modulo prime 0x%x (%d)" % (prime, prime))
			for (pyop, textop) in op2:
				for number1 in numbers:
					for number2 in numbers:
						pystatement = "result = ModInt(0x%x, 0x%x) %s 0x%x" % (number1, prime, pyop, number2)
						try:
							exec(pystatement)
							print("Op2 0x%x %s 0x%x 0x%x 0x%x" % (number1, textop, number2, prime, result.getintvalue()))
						except Exception:
							pass
			for (pyop, textop) in op1:
				for number1 in numbers:
					pystatement = "result = ModInt(0x%x, 0x%x).%s()" % (number1, prime, pyop)
					try:
						exec(pystatement)
						if isinstance(result, int):
							print("Op1 0x%x %s 0x%x 0x%x" % (number1, textop, prime, result))
						elif isinstance(result, tuple):
							print("Op1 0x%x %s 0x%x 0x%x 0x%x" % (number1, textop, prime, result[0].getintvalue(), result[1].getintvalue()))
						elif result is None:
							print("Op1 0x%x %s 0x%x /" % (number1, textop, prime))
						else:
							print("Type? %s" % (type(result)))
					except Exception:
						pass

			print()

