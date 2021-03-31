## Z-Botan

<!--
[![Hackage](https://img.shields.io/hackage/v/Z-Botan.svg?style=flat)](https://hackage.haskell.org/package/Z-Botan)
-->
[![Linux Build Status](https://github.com/ZHaskell/z-botan/workflows/ubuntu-ci/badge.svg)](https://github.com/ZHaskell/z-botan/actions)
[![MacOS Build Status](https://github.com/haskell-Z/z-botan/workflows/osx-ci/badge.svg)](https://github.com/ZHaskell/z-botan/actions)
[![Windows Build Status](https://github.com/ZHaskell/z-botan/workflows/win-ci/badge.svg)](https://github.com/ZHaskell/z-botan/actions)

This package is part of [ZHaskell](https://z.haskell.world) project, providing comprehensive crypto primitives based on [botan](https://github.com/randombit/botan), still under heavy development.

* Random number generators.
* Block Cipher and symmetric cipher.
* Hash.
* MAC.
* Key derivation functions.
* Password hash.
* Constant time multiple precision integers.
* Public key creation, import and export.
* Public key encryption/decryption
* Diffie-Hellman key exchange.
* Signature generation & signature verification.
* X.509 certificates & X.509 certificate revocation lists.
* One time password.

## Requirements

* A working haskell compiler system, GHC(>=8.6), cabal-install(>=2.4), hsc2hs.

* A working python interpreter in `$PATH`.

* Tests need [hspec-discover](https://hackage.haskell.org/package/hspec-discover).

## Example usage

```haskell
> import Z.Crypto
>
```

## Dev guide

```bash
# get code
git clone --recursive git@github.com:ZHaskell/z-botan.git
cd z-botan
# build
cabal build
# test
cabal test --enable-tests --test-show-details=direct
# install
cabal install
# generate document
cabal haddock
```
