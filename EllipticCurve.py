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
import random
import hashlib

from ModInt import ModInt
from AffineCurvePoint import AffineCurvePoint
from ECKeypair import ECKeypair

class EllipticCurve():
	def __init__(self, a, b, p, n, h, Gx, Gy):
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(b, int))		# Curve coefficent B
		assert(isinstance(p, int))		# Modulus
		assert(isinstance(n, int))		# Order
		assert(isinstance(h, int))		# Cofactor
		assert(isinstance(Gx, int))		# Generator Point X
		assert(isinstance(Gy, int))		# Generator Point Y
		self._a = a % p
		self._b = b % p
		self._p = p
		self._n = n
		self._h = h
		if (Gx > 0) and (Gy > 0):
			self._G = AffineCurvePoint(Gx, Gy, self)

		# Check that the curve function is satisfied first
		a = ModInt(a, p)
		b = ModInt(b, p)
		assert(((4 * (a ** 3)) + (27 * (b ** 2))).getintvalue() != 0)

		# Check that G is on the curve
		if (Gx > 0) and (Gy > 0):
			assert(self._G.oncurve())

	def geta(self):
		return self._a
	
	def getb(self):
		return self._b

	def getp(self):
		return self._p
	
	def getn(self):
		return self._n
	
	def getG(self):
		# Return a copy so the curve parameters are immutable
		return self._G.clone()
	
	def genknownkeypair(self, privkey):
		assert(isinstance(privkey, int))
		pubkey = privkey * self._G
		return ECKeypair(self, privkey, pubkey)

	def genkeypair(self):
		privkey = random.randint(0, 100000)
		return self.genknownkeypair(privkey)			

	def getpointwithx(self, x):
		assert(isinstance(x, int))
		rhs = ((ModInt(x, self._p) ** 3) + (self._a * x) + self._b)
		y = rhs.sqrt()
		if y:
			return (AffineCurvePoint(x, y[0].getintvalue(), self), AffineCurvePoint(x, y[1].getintvalue(), self))
		else:
			return None

	# Counts points in curve, including point at infinity (therefore yielding n)
	def countpoints(self):
		curpt = self.getG()
		cnt = 1
		while not curpt.infinity():
			cnt += 1
			curpt += self._G
		return cnt
	
	def getallpoints(self):
		points = [ ]
		curpt = self.getG()
		while not curpt.infinity():
			points.append(curpt.clone())
			curpt += self._G
		return points

	def exploitidenticalnoncesig(self, r, s1, msg1, s2, msg2):
		# Calculate hashes of messages
		e1 = ECKeypair._bytestoint(hashlib.sha1(msg1.encode("utf-8")).digest())
		e2 = ECKeypair._bytestoint(hashlib.sha1(msg2.encode("utf-8")).digest())

		# Take them modulo n
		e1 = ModInt(e1, self.getn())
		e2 = ModInt(e2, self.getn())

		# Recover (supposedly) random nonce
		nonce = (e1 - e2) // (s1 - s2)

		# Recover private key
		priv = ((nonce * s1) - e1) // r

		return { "nonce": nonce, "privatekey": priv }


	def parsablestr(self):
		return "a=0x%x b=0x%x p=0x%x n=0x%x h=0x%x gx=0x%x gy=0x%x" % (self._a, self._b, self._p, self._n, self._h, self._G.getx().getintvalue(), self._G.gety().getintvalue())

	def __str__(self):
		s = ""
		s += "A: 0x%x\n" % (self._a)
		s += "B: 0x%x\n" % (self._b)
		s += "p: 0x%x\n" % (self._p)
		s += "n: 0x%x\n" % (self._n)
		s += "h: %d\n" % (self._h)
		try:
			s += "G: %s" % (str(self._G))
		except AttributeError:
			s += "Without G"
			pass
		return s


if __name__ == "__main__":
	e = EllipticCurve(-3, 5, 23, 0, 0, 13, 22)
	x = AffineCurvePoint(21, 16, e)
	y = AffineCurvePoint(14, 19, e)
	assert(x.oncurve())
	assert(y.oncurve())
	assert((x + y).oncurve())
	assert((x + y) == AffineCurvePoint(14, 4, e))
	assert((x + x).oncurve())
	assert((x + x) == AffineCurvePoint(5, 0, e))
	assert((y + y).oncurve())
	assert((y + y) == AffineCurvePoint(21, 7, e))



	e = EllipticCurve(2, 5, 23, 0, 0, 9, 4)
	x = AffineCurvePoint(9, 4, e)
	y = AffineCurvePoint(10, 6, e)
	# (9, 4) + (10, 6) = (8, 21)
	# (9, 4) + (9, 4) = (6, 16)
	assert(x.oncurve())
	assert(y.oncurve())
	z = x + y	

	assert(z.oncurve())
	z = x + x
	assert(z.oncurve())
	z = y + y
	assert(z.oncurve())

	x = AffineCurvePoint(9, 5, e)
	assert(not x.oncurve())


	# Testing data from http://christelbach.com/ECCalculator.aspx
	e = EllipticCurve(3, 99, 101, 0, 0, 12, 34)
	assert((e.getG() * 0).infinity())
	assert((e.getG() * 1) == e.getG())
	assert((e.getG() * 2) == AffineCurvePoint(93, 88, e))
	assert((e.getG() * 3) == AffineCurvePoint(75, 25, e))
	assert((e.getG() * 4) == AffineCurvePoint(47, 72, e))
	assert((e.getG() * 5) == AffineCurvePoint(21, 63, e))
	assert((e.getG() * 55) == AffineCurvePoint(71, 28, e))
	assert((e.getG() * 123) == AffineCurvePoint(91, 33, e))
	assert((e.getG() * 99).infinity())
	assert(e.countpoints() == 99)


	##################################### Automated tests #####################################
	e = EllipticCurve(
		0xdb7c2abf62e35e668076bead2088, 		# A
		0x659ef8ba043916eede8911702b22, 		# B
		0xdb7c2abf62e35e668076bead208b, 		# p
		0xdb7c2abf62e35e7628dfac6561c5,			# n (order)
		1,										# cofactor
		0x09487239995a5ee76b55f9c2f098,			# G_x
		0xa89ce5af8724c0a23e0e0ff77500			# G_y
	)
	points = [
		AffineCurvePoint(3117110232563059246980187946198621, 3317437604270820210689740076391407, e),
		AffineCurvePoint(1337243996230764682967860953280223, 2063522037029258959118399626141682, e),
		AffineCurvePoint(235253700287668808185890937034851, 830989660091878453658335933918000, e),
		AffineCurvePoint(627781032099779919607023000566247, 1603622602577594429014913566107033, e),
		AffineCurvePoint(1929761220615891268483335561783138, 1546624911677232240933310892908962, e),
		AffineCurvePoint(872432267721461912738308679449077, 2729640644726851734745963545037841, e),
	]
	for i in range(len(points)):
		assert(points[0].oncurve())
	assert(points[0] + points[0] == AffineCurvePoint(4064734346459959837711463108666078, 1633739364791553181243017790342803, e))
	assert(AffineCurvePoint(4064734346459959837711463108666078, 1633739364791553181243017790342803, e).oncurve())
	assert(points[0] + points[1] == AffineCurvePoint(3723026810340743432839738672226419, 539418558131017701255799570461878, e))
	assert(AffineCurvePoint(3723026810340743432839738672226419, 539418558131017701255799570461878, e).oncurve())
	assert(points[0] + points[2] == AffineCurvePoint(2666739795283455355388717400402993, 2972821526814170767052592315049242, e))
	assert(AffineCurvePoint(2666739795283455355388717400402993, 2972821526814170767052592315049242, e).oncurve())
	assert(points[0] + points[3] == AffineCurvePoint(87040431305643233801949973598186, 4174712248394499122322627644575650, e))
	assert(AffineCurvePoint(87040431305643233801949973598186, 4174712248394499122322627644575650, e).oncurve())
	assert(points[0] + points[4] == AffineCurvePoint(2802418382414800560683276089692115, 2630760185865310406957414586693079, e))
	assert(AffineCurvePoint(2802418382414800560683276089692115, 2630760185865310406957414586693079, e).oncurve())
	assert(points[0] + points[5] == AffineCurvePoint(4288609280448373691375140747355688, 420581842128121271226447977613081, e))
	assert(AffineCurvePoint(4288609280448373691375140747355688, 420581842128121271226447977613081, e).oncurve())
	assert(points[1] + points[0] == AffineCurvePoint(3723026810340743432839738672226419, 539418558131017701255799570461878, e))
	assert(AffineCurvePoint(3723026810340743432839738672226419, 539418558131017701255799570461878, e).oncurve())
	assert(points[1] + points[1] == AffineCurvePoint(3591145884720261338103575780699807, 4315217519961907532019414100448261, e))
	assert(AffineCurvePoint(3591145884720261338103575780699807, 4315217519961907532019414100448261, e).oncurve())
	assert(points[1] + points[2] == AffineCurvePoint(767654518279343783442373102239656, 931581834311445282420568360496919, e))
	assert(AffineCurvePoint(767654518279343783442373102239656, 931581834311445282420568360496919, e).oncurve())
	assert(points[1] + points[3] == AffineCurvePoint(3586051730372413391716540216032874, 1732668913318031500067892336307807, e))
	assert(AffineCurvePoint(3586051730372413391716540216032874, 1732668913318031500067892336307807, e).oncurve())
	assert(points[1] + points[4] == AffineCurvePoint(4319220890821527825482144178575612, 723068585981600829545356089627049, e))
	assert(AffineCurvePoint(4319220890821527825482144178575612, 723068585981600829545356089627049, e).oncurve())
	assert(points[1] + points[5] == AffineCurvePoint(3782803895644916151556214584437161, 2771961082269130926455794722149390, e))
	assert(AffineCurvePoint(3782803895644916151556214584437161, 2771961082269130926455794722149390, e).oncurve())
	assert(points[2] + points[0] == AffineCurvePoint(2666739795283455355388717400402993, 2972821526814170767052592315049242, e))
	assert(AffineCurvePoint(2666739795283455355388717400402993, 2972821526814170767052592315049242, e).oncurve())
	assert(points[2] + points[1] == AffineCurvePoint(767654518279343783442373102239656, 931581834311445282420568360496919, e))
	assert(AffineCurvePoint(767654518279343783442373102239656, 931581834311445282420568360496919, e).oncurve())
	assert(points[2] + points[2] == AffineCurvePoint(2120325548453476461903987486245115, 2843555047937458025861854944861757, e))
	assert(AffineCurvePoint(2120325548453476461903987486245115, 2843555047937458025861854944861757, e).oncurve())
	assert(points[2] + points[3] == AffineCurvePoint(2869160181194689537159393771033225, 2388609795801451355008363813919312, e))
	assert(AffineCurvePoint(2869160181194689537159393771033225, 2388609795801451355008363813919312, e).oncurve())
	assert(points[2] + points[4] == AffineCurvePoint(1443848317651251533912280184260615, 3507966784103250297258176930645556, e))
	assert(AffineCurvePoint(1443848317651251533912280184260615, 3507966784103250297258176930645556, e).oncurve())
	assert(points[2] + points[5] == AffineCurvePoint(1528876984675717023713801774301100, 3700884665652262932134185881457463, e))
	assert(AffineCurvePoint(1528876984675717023713801774301100, 3700884665652262932134185881457463, e).oncurve())
	assert(points[3] + points[0] == AffineCurvePoint(87040431305643233801949973598186, 4174712248394499122322627644575650, e))
	assert(AffineCurvePoint(87040431305643233801949973598186, 4174712248394499122322627644575650, e).oncurve())
	assert(points[3] + points[1] == AffineCurvePoint(3586051730372413391716540216032874, 1732668913318031500067892336307807, e))
	assert(AffineCurvePoint(3586051730372413391716540216032874, 1732668913318031500067892336307807, e).oncurve())
	assert(points[3] + points[2] == AffineCurvePoint(2869160181194689537159393771033225, 2388609795801451355008363813919312, e))
	assert(AffineCurvePoint(2869160181194689537159393771033225, 2388609795801451355008363813919312, e).oncurve())
	assert(points[3] + points[3] == AffineCurvePoint(176878457604457698579663631864190, 721471289065271224834385424962611, e))
	assert(AffineCurvePoint(176878457604457698579663631864190, 721471289065271224834385424962611, e).oncurve())
	assert(points[3] + points[4] == AffineCurvePoint(2562156057939871711326640460445945, 3577511574269877768475169588752653, e))
	assert(AffineCurvePoint(2562156057939871711326640460445945, 3577511574269877768475169588752653, e).oncurve())
	assert(points[3] + points[5] == AffineCurvePoint(148146258284214251215275786030378, 1329592514181691255155018041558553, e))
	assert(AffineCurvePoint(148146258284214251215275786030378, 1329592514181691255155018041558553, e).oncurve())
	assert(points[4] + points[0] == AffineCurvePoint(2802418382414800560683276089692115, 2630760185865310406957414586693079, e))
	assert(AffineCurvePoint(2802418382414800560683276089692115, 2630760185865310406957414586693079, e).oncurve())
	assert(points[4] + points[1] == AffineCurvePoint(4319220890821527825482144178575612, 723068585981600829545356089627049, e))
	assert(AffineCurvePoint(4319220890821527825482144178575612, 723068585981600829545356089627049, e).oncurve())
	assert(points[4] + points[2] == AffineCurvePoint(1443848317651251533912280184260615, 3507966784103250297258176930645556, e))
	assert(AffineCurvePoint(1443848317651251533912280184260615, 3507966784103250297258176930645556, e).oncurve())
	assert(points[4] + points[3] == AffineCurvePoint(2562156057939871711326640460445945, 3577511574269877768475169588752653, e))
	assert(AffineCurvePoint(2562156057939871711326640460445945, 3577511574269877768475169588752653, e).oncurve())
	assert(points[4] + points[4] == AffineCurvePoint(3074072036822685021436989941342785, 3157984599511588306440992673720004, e))
	assert(AffineCurvePoint(3074072036822685021436989941342785, 3157984599511588306440992673720004, e).oncurve())
	assert(points[4] + points[5] == AffineCurvePoint(2219827979145724699972786737693217, 4167759417703712591322494207750534, e))
	assert(AffineCurvePoint(2219827979145724699972786737693217, 4167759417703712591322494207750534, e).oncurve())
	assert(points[5] + points[0] == AffineCurvePoint(4288609280448373691375140747355688, 420581842128121271226447977613081, e))
	assert(AffineCurvePoint(4288609280448373691375140747355688, 420581842128121271226447977613081, e).oncurve())
	assert(points[5] + points[1] == AffineCurvePoint(3782803895644916151556214584437161, 2771961082269130926455794722149390, e))
	assert(AffineCurvePoint(3782803895644916151556214584437161, 2771961082269130926455794722149390, e).oncurve())
	assert(points[5] + points[2] == AffineCurvePoint(1528876984675717023713801774301100, 3700884665652262932134185881457463, e))
	assert(AffineCurvePoint(1528876984675717023713801774301100, 3700884665652262932134185881457463, e).oncurve())
	assert(points[5] + points[3] == AffineCurvePoint(148146258284214251215275786030378, 1329592514181691255155018041558553, e))
	assert(AffineCurvePoint(148146258284214251215275786030378, 1329592514181691255155018041558553, e).oncurve())
	assert(points[5] + points[4] == AffineCurvePoint(2219827979145724699972786737693217, 4167759417703712591322494207750534, e))
	assert(AffineCurvePoint(2219827979145724699972786737693217, 4167759417703712591322494207750534, e).oncurve())
	assert(points[5] + points[5] == AffineCurvePoint(137680862920165800159415222573783, 3475375738534728619472562866721341, e))
	assert(AffineCurvePoint(137680862920165800159415222573783, 3475375738534728619472562866721341, e).oncurve())
	assert(244731188 * points[0] == AffineCurvePoint(799343867892131331328116631700028, 3238045619580805561449053238064641, e))
	assert(AffineCurvePoint(799343867892131331328116631700028, 3238045619580805561449053238064641, e).oncurve())
	assert(479215585 * points[0] == AffineCurvePoint(2706730081538110138078384782047852, 2881713554078961053511508101371441, e))
	assert(AffineCurvePoint(2706730081538110138078384782047852, 2881713554078961053511508101371441, e).oncurve())
	assert(615977890 * points[0] == AffineCurvePoint(3838979374142936020593894026971284, 2353562327773064373435074287667816, e))
	assert(AffineCurvePoint(3838979374142936020593894026971284, 2353562327773064373435074287667816, e).oncurve())
	assert(550140093 * points[0] == AffineCurvePoint(200065277622376526049681520014276, 51209742086984118724200802806153, e))
	assert(AffineCurvePoint(200065277622376526049681520014276, 51209742086984118724200802806153, e).oncurve())
	assert(540588643 * points[0] == AffineCurvePoint(2708454351094974414186353284132004, 482908022980745877814430356771611, e))
	assert(AffineCurvePoint(2708454351094974414186353284132004, 482908022980745877814430356771611, e).oncurve())
	assert(672739461 * points[0] == AffineCurvePoint(1030814758650133152061550844236032, 1823080711222015183880343693623151, e))
	assert(AffineCurvePoint(1030814758650133152061550844236032, 1823080711222015183880343693623151, e).oncurve())
	assert(910647265 * points[1] == AffineCurvePoint(137737857707196532599472608676360, 957907527391095020531740031338079, e))
	assert(AffineCurvePoint(137737857707196532599472608676360, 957907527391095020531740031338079, e).oncurve())
	assert(399781155 * points[1] == AffineCurvePoint(3761977973845283625480428585967217, 2353350788128670145920555879879491, e))
	assert(AffineCurvePoint(3761977973845283625480428585967217, 2353350788128670145920555879879491, e).oncurve())
	assert(438499287 * points[1] == AffineCurvePoint(791784310872674310944665210228985, 1430904795413769943854621265242346, e))
	assert(AffineCurvePoint(791784310872674310944665210228985, 1430904795413769943854621265242346, e).oncurve())
	assert(30329342 * points[1] == AffineCurvePoint(842488465058721644608558481954980, 3887929284060323035133050694924699, e))
	assert(AffineCurvePoint(842488465058721644608558481954980, 3887929284060323035133050694924699, e).oncurve())
	assert(967116404 * points[1] == AffineCurvePoint(4155601987656967768431349496277491, 192440768853698673613506368932279, e))
	assert(AffineCurvePoint(4155601987656967768431349496277491, 192440768853698673613506368932279, e).oncurve())
	assert(927133616 * points[1] == AffineCurvePoint(2556810828429079101914439119665354, 2524847108175393854549561825759512, e))
	assert(AffineCurvePoint(2556810828429079101914439119665354, 2524847108175393854549561825759512, e).oncurve())
	assert(206990082 * points[2] == AffineCurvePoint(1707574986822913143399470421926442, 131328589915508399663105547392277, e))
	assert(AffineCurvePoint(1707574986822913143399470421926442, 131328589915508399663105547392277, e).oncurve())
	assert(145434778 * points[2] == AffineCurvePoint(193470908356734603666578767473410, 3004503290193422403586016715967043, e))
	assert(AffineCurvePoint(193470908356734603666578767473410, 3004503290193422403586016715967043, e).oncurve())
	assert(454728583 * points[2] == AffineCurvePoint(4400079036925892699736681855331890, 3088617866065122674311000109236495, e))
	assert(AffineCurvePoint(4400079036925892699736681855331890, 3088617866065122674311000109236495, e).oncurve())
	assert(135155369 * points[2] == AffineCurvePoint(2027712979252276636045660473448539, 2164103391295458545875249924786406, e))
	assert(AffineCurvePoint(2027712979252276636045660473448539, 2164103391295458545875249924786406, e).oncurve())
	assert(3646348 * points[2] == AffineCurvePoint(222482181719241110158914176464073, 1175253763932995577527931926137281, e))
	assert(AffineCurvePoint(222482181719241110158914176464073, 1175253763932995577527931926137281, e).oncurve())
	assert(510578945 * points[2] == AffineCurvePoint(1261291574979275348201458226343995, 3102733652715577691117533666551442, e))
	assert(AffineCurvePoint(1261291574979275348201458226343995, 3102733652715577691117533666551442, e).oncurve())
	assert(773473903 * points[3] == AffineCurvePoint(741959927009188871583680615949638, 2093971120945716035639075368016278, e))
	assert(AffineCurvePoint(741959927009188871583680615949638, 2093971120945716035639075368016278, e).oncurve())
	assert(997111420 * points[3] == AffineCurvePoint(1248100720882585714838579280838399, 4438594924170079853980619795252553, e))
	assert(AffineCurvePoint(1248100720882585714838579280838399, 4438594924170079853980619795252553, e).oncurve())
	assert(668321744 * points[3] == AffineCurvePoint(395886649333065339235666595510340, 3755881760237441545879003514708540, e))
	assert(AffineCurvePoint(395886649333065339235666595510340, 3755881760237441545879003514708540, e).oncurve())
	assert(829980073 * points[3] == AffineCurvePoint(1735323911926967505958820072450473, 1405878229247618255874049365208656, e))
	assert(AffineCurvePoint(1735323911926967505958820072450473, 1405878229247618255874049365208656, e).oncurve())
	assert(441912688 * points[3] == AffineCurvePoint(2904753317362970167836831382358365, 1137554067721498868296881430795660, e))
	assert(AffineCurvePoint(2904753317362970167836831382358365, 1137554067721498868296881430795660, e).oncurve())
	assert(970575074 * points[3] == AffineCurvePoint(313100336875746517104210806321395, 2084520610118571098315493974262361, e))
	assert(AffineCurvePoint(313100336875746517104210806321395, 2084520610118571098315493974262361, e).oncurve())
	assert(606215582 * points[4] == AffineCurvePoint(2850264680963666931636271668878004, 2167820720348711946721651674088979, e))
	assert(AffineCurvePoint(2850264680963666931636271668878004, 2167820720348711946721651674088979, e).oncurve())
	assert(968223364 * points[4] == AffineCurvePoint(752966669767470049793829658672502, 817295934273335397573319216079235, e))
	assert(AffineCurvePoint(752966669767470049793829658672502, 817295934273335397573319216079235, e).oncurve())
	assert(26106169 * points[4] == AffineCurvePoint(404431198475874236899098181363662, 2296789183245184747073488685011926, e))
	assert(AffineCurvePoint(404431198475874236899098181363662, 2296789183245184747073488685011926, e).oncurve())
	assert(379289443 * points[4] == AffineCurvePoint(723353446510304113034686043795598, 292865962596212029663654924152756, e))
	assert(AffineCurvePoint(723353446510304113034686043795598, 292865962596212029663654924152756, e).oncurve())
	assert(523987778 * points[4] == AffineCurvePoint(825694777938573065404675043994059, 1338729390845431942346396395449572, e))
	assert(AffineCurvePoint(825694777938573065404675043994059, 1338729390845431942346396395449572, e).oncurve())
	assert(885647483 * points[4] == AffineCurvePoint(801298464780419945624371970788438, 4072001729606023524262744717618362, e))
	assert(AffineCurvePoint(801298464780419945624371970788438, 4072001729606023524262744717618362, e).oncurve())
	assert(634165049 * points[5] == AffineCurvePoint(314787966440069146423812028140757, 3759178934144635742129828380139388, e))
	assert(AffineCurvePoint(314787966440069146423812028140757, 3759178934144635742129828380139388, e).oncurve())
	assert(406547467 * points[5] == AffineCurvePoint(3915579942088610581276212551825744, 1735075139758492739634365954880527, e))
	assert(AffineCurvePoint(3915579942088610581276212551825744, 1735075139758492739634365954880527, e).oncurve())
	assert(977999735 * points[5] == AffineCurvePoint(4047764598782335211666165260642656, 3390395305328029707188373076630799, e))
	assert(AffineCurvePoint(4047764598782335211666165260642656, 3390395305328029707188373076630799, e).oncurve())
	assert(59143884 * points[5] == AffineCurvePoint(4142931471858723228703092484057487, 1211817578182076750442156342501316, e))
	assert(AffineCurvePoint(4142931471858723228703092484057487, 1211817578182076750442156342501316, e).oncurve())
	assert(130367752 * points[5] == AffineCurvePoint(2080598045063511954398353433475040, 3372609893215355160406007246405785, e))
	assert(AffineCurvePoint(2080598045063511954398353433475040, 3372609893215355160406007246405785, e).oncurve())
	assert(537668229 * points[5] == AffineCurvePoint(2137496744785763901399697229984622, 4394820220824082213468385758117630, e))
	assert(AffineCurvePoint(2137496744785763901399697229984622, 4394820220824082213468385758117630, e).oncurve())

	if (len(sys.argv) == 2) and (sys.argv[1] == "gentcdata"):
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
		scalars = [ ]
		scalars += list(range(100))
		scalars += [ 2 ** i for i in list(range(0, 32)) ]
		scalars += [ (2 ** i) - 1 for i in list(range(0, 32)) ]
		scalars += [ (2 ** 128) - 1, (2 ** 128) ]
		for (curvename, curve) in curves.items():
			scalars.append(curve.getp())
			scalars.append(curve.getn() - 1)
			scalars.append(curve.getn())
			scalars.append(curve.getn() + 1)
			scalars.append(curve.getn() * 2)
			scalars.append(curve.getn() * 3)
			scalars.append(curve.getn() * 10)
		for i in range(5):
			scalars.append(random.randint(2 ** 10, 2 ** 11))
		for i in range(5):
			scalars.append(random.randint(2 ** 20, 2 ** 21))
		for i in range(5):
			scalars.append(random.randint(2 ** 128, 2 ** 129))
		for i in range(5):
			scalars.append(random.randint(2 ** 300, 2 ** 301))
		scalars = sorted(list(set(scalars)))

		print("# Testcase data for scalar curve multiplication operation")
		print()
		print("# Format: NewCurve [Name] [Parameters]")
		print("# Followed by           : Point [Scalar] [PointX] [PointY]")
		print("# or for Pt. at infinity: PointInfty [Scalar]")
		print()
		for (curvename, curve) in curves.items():
			print("NewCurve %s %s" % (curvename, curve.parsablestr()))
			for scalar in scalars:
				result = scalar * curve.getG()
				if not result.infinity():
					print("Point 0x%x 0x%x 0x%x" % (scalar, result.getx().getintvalue(), result.gety().getintvalue()))
				else:
					print("PointInfty 0x%x" % (scalar))
			print()
