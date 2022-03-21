# toyecc
[![Build Status](https://app.travis-ci.com/johndoe31415/toyecc.svg?branch=master)](https://app.travis-ci.com/johndoe31415/toyecc)

toyecc is a playground for Elliptic Curve Cryptography in F<sub>P</sub>. It is
written in pure Python and aims to explain ECC in easy terms. It is neither
written to be performant, nor side-channel resistant nor in any way suited for
productive use at all. Please use it for its intended purpose and for it only.

The rationale behind toyecc is to show a clear and mathematically clean
presentation of the underlying mathematical problems. Most code that is written
arund ECC -- especially code that revolves around Ed25519 and/or Curve25519 is
heavily optimized and in many cases hard to understand. toyecc tries to present
the problems with a high level of abstraction in order to serve as yet another
(different) reference to compare implementations against and in order to aid
understanding of heavily optimized code. All curve arithmetic is therefore
performed in affine space; performance in affine space is lowest, but having
values that directly can be checked against the curve equation makes
understanding everything extremely easy.


## Tutorial
There's a ECC tutorial that I've written which accompanies the pure code. It
can be found at [http://johannes-bauer.com/compsci/ecc/](http://johannes-bauer.com/compsci/ecc/)


## Features
  * ECDSA demonstration
  * ECIES demonstration
  * ECDH demonstration
  * Elgamal demonstration
  * Dual_EC_DBRG backdoor demonstration
  * Demonstration how a private key can be recovered from two ECDSA signatures
    which reused the same nonce (ECDSA nonce exploit)
  * Support for short-formed Weierstrass curves, Montgomery curves and twisted
    Edwards curves
  * Conversion of domain parameters of twisted Edwards to Montgomery form and
    back, conversion of points between Montgomery representation and its
    birationally equivalent twisted Edwards counterpart
  * Ed25519 and Curve25519 support and support to convert keys between each
    other (Curve25519 and Ed25519 are birationally equivalent curves)
  * Many testcases to try out your own implementation
  * Example of OpenBSD's signify application (generates and verifies Ed25519
    signatures, but doesn't support key encryption)
  * X-coordinate-only scalar multiplication on Short Weierstrass curves
  * Clean, well-documented Python3 code

## License
GNU GPL-3.
