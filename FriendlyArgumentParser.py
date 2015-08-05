#!/usr/bin/python3
#
#	FriendlyArgumentParser - Argument parser with default help pages
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
#	File UUID c55a0ea0-6dc8-4ceb-a9ff-e54ea8a2ea62

import sys
import argparse
import textwrap

class FriendlyArgumentParser(argparse.ArgumentParser):
	def __init__(self, *args, **kwargs):
		argparse.ArgumentParser.__init__(self, *args, **kwargs)
		self.__silent_error = False

	def setsilenterror(self, silenterror):
		self.__silent_error = silenterror

	def error(self, msg):
		if self.__silent_error:
			raise Exception(msg)
		else:
			for line in textwrap.wrap("Error: %s" % (msg), subsequent_indent = "  "):
				print(line, file = sys.stderr)
			print(file = sys.stderr)
			self.print_help(file = sys.stderr)
			sys.exit(1)

def baseint(value, default_base = 10):
	if value.lower().startswith("0x"):
		return int(value, 16)
	elif value.lower().startswith("0b"):
		return int(value, 2)
	elif value.lower().startswith("0o"):
		return int(value, 8)
	elif value.lower().startswith("0b"):
		return int(value, 2)
	else:
		return int(value, default_base)

if __name__ == "__main__":
	parser = FriendlyArgumentParser()
	parser.add_argument("-d", "--dbfile", metavar = "filename", type = str, default = "mydb.sqlite", help = "Specifies database file to use. Defaults to %(default)s.")
	parser.add_argument("-f", "--force", action = "store_true", help = "Do not ask for confirmation")
	parser.add_argument("-x", metavar = "hexint", type = baseint, default = "0x100", help = "Defaults to %(default)s.")
	parser.add_argument("qids", metavar = "qid", type = int, nargs = "+", help = "Question ID(s) of the question(s) to be edited")
	args = parser.parse_args(sys.argv[1:])
	print(args)


