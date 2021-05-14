## Z-Botan

[![Hackage](https://img.shields.io/hackage/v/Z-Botan.svg?style=flat)](https://hackage.haskell.org/package/Z-Botan)
[![Linux Build Status](https://github.com/ZHaskell/z-botan/workflows/ubuntu-ci/badge.svg)](https://github.com/ZHaskell/z-botan/actions)
[![MacOS Build Status](https://github.com/haskell-Z/z-botan/workflows/osx-ci/badge.svg)](https://github.com/ZHaskell/z-botan/actions)
[![Windows Build Status](https://github.com/ZHaskell/z-botan/workflows/win-ci/badge.svg)](https://github.com/ZHaskell/z-botan/actions)
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.svg)](https://gitter.im/Z-Haskell/community)
<a href="https://opencollective.com/zhaskell/donate" target="_blank">
  <img src="https://opencollective.com/zhaskell/donate/button@2x.png?color=blue" width=128 />
</a>

This package is part of [ZHaskell](https://z.haskell.world) project, providing comprehensive crypto primitives based on [botan](https://github.com/randombit/botan).

* Random number generators.
* Block Cipher and symmetric cipher.
* Hash.
* MAC.
* Key derivation functions.
* Password hash.
* Multiple precision integers.
* Public key creation, import and export.
* Public key encryption/decryption
* Diffie-Hellman key exchange.
* Signature generation & signature verification.
* X.509 certificates & X.509 certificate revocation lists.
* One time password.
* AES Key Wrapping
* Format Preserving Encryption.

## Requirements

* A working haskell compiler system, GHC(>=8.6), cabal-install(>=2.4), hsc2hs.

* A working python interpreter in `$PATH`.

* Tests need [hspec-discover](https://hackage.haskell.org/package/hspec-discover).

## Example usage

```haskell
> :set -XOverloadedLists
> :m + Z.Crypto.Hash Z.Data.Vector.Hex 
>
> hash MD5 "hello, world"
[228,215,241,180,237,46,66,209,88,152,244,178,123,1,157,164]
> HexBytes $ hash SHA256  "hello, world"
09CA7E4EAA6E8AE9C7D261167129184883644D07DFBA7CBFBC4C8A2E08360D5B
>
> :m + Z.Crypto.RNG Z.Crypto.PwdHash 
> genBcrypt "mypass" rng 8
[36,50,97,36,48,56,36,102,82,102,78,76,71,122,106,78,80,99,100,68,69,77,75,70,81,104,76,97,117,110,86,52,88,53,89,47,88,101,81,117,80,111,111,111,65,109,122,48,97,50,66,55,79,104,56,104,54,66,121,109]
> validBcrypt "mypass" [36,50,97,36,48,56,36,102,82,102,78,76,71,122,106,78,80,99,100,68,69,77,75,70,81,104,76,97,117,110,86,52,88,53,89,47,88,101,81,117,80,111,111,111,65,109,122,48,97,50,66,55,79,104,56,104,54,66,121,109]
True
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
