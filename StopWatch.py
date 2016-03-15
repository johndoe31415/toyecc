#!/usr/bin/python3
#
#	StopWatch - Simple abstraction class for timing using context managers.
#	Copyright (C) 2011-2012 Johannes Bauer
#
#	This file is part of jpycommon.
#
#	jpycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	jpycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with jpycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID 25454b15-67f7-4287-afbd-d6168a30cc9f

import time

class StopWatch(object):
	def __init__(self, component = None, noisy = False):
		self._component = component
		self._noisy = noisy
		self.reset()

	@property
	def finishtime(self):
		return self._finishtime

	def stop(self):
		self._finishtime = time.time() - self._t
		return self.finishtime

	def finish(self):
		self._finishtime = self.stop()
		if self._noisy:
			print("%s took %s" % (self._component, str(self)))

	def reset(self):
		self._finishtime = None
		self._t = time.time()

	def __str__(self):
		t = self.stop()
		if t < 1:
			return "%d ms" % (round(1000 * t))
		elif t < 10:
			return "%.1f sec" % (t)
		else:
			tint = round(t)
			if tint < 60:
				return "%d sec" % (tint)
			elif tint < 3600:
				return "%d:%02d m:s" % (tint // 60, tint % 60)
			elif tint < 86400:
				return "%d:%02d:%02d h:m:s" % (tint // 3600, tint % 3600 // 60, tint % 3600 % 60)
			else:
				return "%d-%d:%02d:%02d d-h:m:s" % (tint // 86400, tint % 86400 // 3600, tint % 86400 % 3600 // 60, tint % 86400 % 3600 % 60)

	def __enter__(self):
		self.reset()

	def __exit__(self, type, value, traceback):
		self.finish()

if __name__ == "__main__":
	x = StopWatch("foobar", True)
	time.sleep(0.1)
	x.finish()
	print(x.finishtime)

	with StopWatch("foobar2", True):
		time.sleep(0.1)

