import setuptools
import toyecc

with open("README.md") as f:
	long_description = f.read()

setuptools.setup(
	name = "toyecc",
	packages = setuptools.find_packages(),
	version = toyecc.VERSION,
	license = "gpl-3.0",
	description = "Elliptic Curve Cryptography playground/toolkit written in pure Python",
	long_description = long_description,
	long_description_content_type = "text/markdown",
	author = "Johannes Bauer",
	author_email = "joe@johannes-bauer.com",
	url = "https://github.com/johndoe31415/toyecc",
	download_url = "https://github.com/johndoe31415/toyecc/archive/v" + toyecc.VERSION + ".tar.gz",
	keywords = [ "elliptic", "curve", "cryptography", "ed25519", "ecdsa", "ecdh", "montgomery", "edwards", "weierstrass" ],
	install_requires = [
		"pyasn1",
	],
#	entry_points = {
#		"console_scripts": [
#			"toyecc = toyecc.__main__:main"
#		]
#	},
	include_package_data = False,
	classifiers = [
		"Development Status :: 5 - Production/Stable",
		"Intended Audience :: Developers",
		"License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 3 :: Only",
		"Programming Language :: Python :: 3.5",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: 3.7",
		"Programming Language :: Python :: 3.8",
		"Programming Language :: Python :: 3.9",
	],
)
