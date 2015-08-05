#!/usr/bin/python3
#
#	PrefixMatcher - Match the shortest unambiguous prefix
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
#	File UUID f75ad3fb-12d0-4368-b14b-9353df125800

class PrefixMatcher(object):
	def __init__(self, options):
		self._opts = options

	def matchunique(self, value):
		result = self.match(value)
		if len(result) != 1:
			if len(result) == 0:
				raise Exception("'%s' did not match any options." % (value))
			else:
				raise Exception("'%s' is ambiguous. Please clarify further. Available: %s" % (value, ", ".join(sorted(list(result)))))
		return result[0]

	def match(self, value):
		return [ option for option in self._opts if option.startswith(value) ]

if __name__ == "__main__":
	pm = PrefixMatcher([ "import", "install", "foo" ])

	print(pm.match("i"))
	print(pm.matchunique("i"))
