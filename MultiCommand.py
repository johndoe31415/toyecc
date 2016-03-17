#!/usr/bin/python3
#
#	MultiCommand - Provide an openssl-style multi-command abstraction
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
#	File UUID 4c6b89d0-ec0c-4b19-80d1-4daba7d80967

import sys
import textwrap
import collections

from FriendlyArgumentParser import FriendlyArgumentParser
from PrefixMatcher import PrefixMatcher

class MultiCommand(object):
	RegisteredCommand = collections.namedtuple("RegisteredCommand", [ "name", "description", "parsergenerator", "action", "aliases" ])
	ParseResult = collections.namedtuple("ParseResults", [ "cmd", "args" ])

	def __init__(self, help = None):
		self._help = help
		self._commands = { }
		self._aliases = { }
		self._cmdorder = [ ]

	def register(self, commandname, description, parsergenerator, **kwargs):
		supported_kwargs = set(("aliases", "action"))
		if len(set(kwargs.keys()) - supported_kwargs) > 0:
			raise Exception("Unsupported kwarg found. Supported: %s" % (", ".join(sorted(list(supported_kwargs)))))

		if (commandname in self._commands) or (commandname in self._aliases):
			raise Exception("Command '%s' already registered." % (commandname))

		aliases = kwargs.get("aliases", [ ])
		action = kwargs.get("action")
		for alias in aliases:
			if (alias in self._commands) or (alias in self._aliases):
				raise Exception("Alias '%s' already registered." % (alias))
			self._aliases[alias] = commandname

		cmd = self.RegisteredCommand(commandname, description, parsergenerator, action, aliases)
		self._commands[commandname] = cmd
		self._cmdorder.append(commandname)

	def _show_syntax(self, msg = None):
		if msg is not None:
			print("Error: %s" % (msg), file = sys.stderr)
		if self._help is not None:
			print()
			for line in textwrap.wrap(self._help):
				print(line)
			print()
		print("Syntax: %s [command] [options]" % (sys.argv[0]), file = sys.stderr)
		print(file = sys.stderr)
		print("Available commands:", file = sys.stderr)
		for commandname in self._cmdorder:
			command = self._commands[commandname]
			print("    %-15s    %s" % (command.name, command.description))
		print(file = sys.stderr)
		print("Options vary from command to command. To receive further info, type", file = sys.stderr)
		print("    %s [command] --help" % (sys.argv[0]), file = sys.stderr)

	def _raise_error(self, msg, silent = False):
		if silent:
			raise Exception(msg)
		else:
			self._show_syntax(msg)
			sys.exit(1)

	def _getcmdnames(self):
		return set(self._commands.keys()) | set(self._aliases.keys())

	def parse(self, cmdline, silent = False):
		if len(cmdline) < 1:
			self._raise_error("No command supplied.")

		# Check if we can match the command portion
		pm = PrefixMatcher(self._getcmdnames())
		try:
			supplied_cmd = pm.matchunique(cmdline[0])
		except Exception as e:
			self._raise_error("Invalid command supplied: %s" % (str(e)))

		if supplied_cmd in self._aliases:
			supplied_cmd = self._aliases[supplied_cmd]

		command = self._commands[supplied_cmd]
		parser = FriendlyArgumentParser(prog = sys.argv[0] + " " + command.name, description = command.description, add_help = False)
		command.parsergenerator(parser)
		parser.setsilenterror(silent)
		args = parser.parse_args(cmdline[1:])
		return self.ParseResult(command, args)

	def run(self, cmdline, silent = False):
		parseresult = self.parse(cmdline, silent)
		if parseresult.cmd.action is None:
			raise Exception("Should run command '%s', but no action was registered." % (parseresult.cmd.name))
		parseresult.cmd.action(parseresult.cmd.name, parseresult.args)

if __name__ == "__main__":
	mc = MultiCommand()

	def importaction(cmd, args):
		print("Import:", cmd, args)

	class ExportAction(object):
		def __init__(self, cmd, args):
			print("Export:", cmd, args)

	def genparser(parser):
		parser.add_argument("-i", "--infile", metavar = "filename", type = str, required = True, help = "Specifies the input text file that is to be imported. Mandatory argument.")
		parser.add_argument("--verbose", action = "store_true", help = "Increase verbosity during the importing process.")
		parser.add_argument("-n", "--world", metavar = "name", type = str, choices = [ "world", "foo", "bar" ], default = "overworld", help = "Specifies the world name. Possible options are %(choices)s. Default is %(default)s.")
	mc.register("import", "Import some file from somewhere", genparser, action = importaction, aliases = [ "ymport" ])


	def genparser(parser):
		parser.add_argument("-o", "--outfile", metavar = "filename", type = str, required = True, help = "Specifies the input text file that is to be imported. Mandatory argument.")
		parser.add_argument("--verbose", action = "store_true", help = "Increase verbosity during the importing process.")
	mc.register("export", "Export some file to somewhere", genparser, action = ExportAction)

	mc.run(sys.argv[1:])

