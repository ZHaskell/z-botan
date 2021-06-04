# Revision history for z-botan

## 0.4.0.0  -- 2020-06-06

* Add `Z.Crypto.SafeMem` module to improve memory safety:
    * Add `Password` type to enforce compare password by using password hash.
    * Add `CEBytes` with contant time equal comparing.
    * Add `Secret` with OS locking and auto zeroing.
* Add `StreamCipher` to `Z.Crypto.Cipher`, change `cipherBIO` to `streamCipherBIO` to use `StreamCipher` only.
* Rewrite AEAD/cipher mode interface to expose AEAD API only.
* Add more tests.

## 0.3.1.0  -- 2020-05-14

* Change `cipherBIO` to buffer an extra chunk so that the last chunk is larger than minimum final chunk size, add a file encryption example.

## 0.3.0.0  -- 2020-05-14

* Change `EMEPadding` to `EncParam`, add `SM2EncParam`.
* Change `EMSA` to `SignParam`, add `Ed25519Pure`, `Ed25519ph`, `Ed25519Hash`, `SM2SignParam`.
* Change PubKey decrypt, verify type to `IO`. 

## 0.2.0.0  -- 2020-05-12

* Simplify `KeyType` in `Z.Crypto.PubKey`.
* Add `sm2Encrypt`, `sm2Decrypt` to `Z.Crypto.PubKey`.
* Add `systemCertStore`, `mozillaCertStore` to `Z.Crypto.X509`.

## 0.1.1.2  -- 2020-05-11

* Export `KeySpec` from `Z.Crypto.Cipher`.

## 0.1.0.0  -- 2020-05-11

* The very first release.
