#!/usr/bin/python3
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

import time
import sys
from ecc import getcurvebyname, ECPrivateKey
from StopWatch import StopWatch

curve = getcurvebyname("ed25519")

if len(sys.argv) < 2:
	keypair = ECPrivateKey.eddsa_generate(curve)
	print("Generating keypair on the fly")
else:
	keypair = ECPrivateKey.loadkeypair(bytes.fromhex(sys.argv[1]))
print("Keypair:", keypair)

msg = b"Foobar!"
print("Message:", msg)

signature = keypair.eddsa_sign(msg)
print("Signature:", signature)

print("Verify correct message: %s (should be True)" % (keypair.pubkey.eddsa_verify(msg, signature)))
print("Verify forged message : %s (should be False)" % (keypair.pubkey.eddsa_verify(msg + b"x", signature)))

