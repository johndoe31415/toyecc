joeecc
=======
joeecc is a playground for Elliptic Curve Cryptography in F<sub>P</sub>. It is
written in pure Python and aims to explain ECC in easy terms. It is neither
written to be performant, nor side-channel resistant nor in any way suited for
productive use at all. Please use it for its intended purpose and for it only.


Tutorial
--------
There's a ECC tutorial that I've written which accompanies the pure code. It
can be found at

   http://johannes-bauer.com/compsci/ecc/


Features
--------
  * ECDSA demonastration
  * ECIES demonstration
  * ECDH demonstration
  * Demonstration how key recovery can be done when nonces are reused within
    ECDSA
  * Curve25519 support
  * Example of OpenBSD's signify application (generates and verifies Curve25519
    signatures)
  * Many testcases to try out your own implementation
  * Clean Python3 code


