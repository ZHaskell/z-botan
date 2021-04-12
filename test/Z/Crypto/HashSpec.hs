{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.HashSpec where

import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.IO.FileSystem    as FS
import qualified Z.Data.Text        as T
import           Z.Crypto.Hash
import           Utils

spec :: Spec
spec = describe "Crypto.Hash" $ do
    forM_
        [ ("adler32.vec", "Adler32", Adler32)
        , ("blake2b.vec", "BLAKE2b(224)", BLAKE2b 224)
        , ("blake2b.vec", "BLAKE2b(256)", BLAKE2b 256)
        , ("blake2b.vec", "BLAKE2b(384)", BLAKE2b 384)
        , ("blake2b.vec", "BLAKE2b(512)", BLAKE2b 512)
        , ("comp4p.vec", "Comb4P(MD4,MD5)", Comb4P MD4 MD5)
        , ("crc24.vec", "CRC24", CRC24)
        , ("crc32.vec", "CRC32", CRC32)
        , ("keccak.vec", "Keccak-1600(224)", Keccak1600_224)
        , ("keccak.vec", "Keccak-1600(256)", Keccak1600_256)
        , ("keccak.vec", "Keccak-1600(384)", Keccak1600_384)
        , ("keccak.vec", "Keccak-1600(512)", Keccak1600_512)
        , ("md4.vec", "MD4", MD4)
        , ("md5.vec", "MD5", MD5)
        , ("parallel.vec", "Parallel(MD5,SHA-160)", Parallel MD5 SHA160)
        , ("parallel.vec", "Parallel(SHA-256,SHA-512)", Parallel SHA256 SHA512)
        , ("ripemd160.vec", "RIPEMD-160", RIPEMD160)
        , ("sha1.vec", "SHA-160", SHA160)
        , ("sha2_32.vec", "SHA-224", SHA224)
        , ("sha2_32.vec", "SHA-256", SHA256)
        , ("sha2_64.vec", "SHA-384", SHA384)
        , ("sha2_64.vec", "SHA-512", SHA512)
        , ("sha2_64.vec", "SHA-512-256", SHA512_256)
        , ("sha3.vec", "SHA-3(224)", SHA3_224)
        , ("sha3.vec", "SHA-3(256)", SHA3_256)
        , ("sha3.vec", "SHA-3(384)", SHA3_384)
        , ("sha3.vec", "SHA-3(512)", SHA3_512)
        , ("shake.vec", "SHAKE-128(128)", SHAKE128 128)
        , ("shake.vec", "SHAKE-256(256)", SHAKE256 256)
        , ("shake.vec", "SHAKE-128(1120)", SHAKE128 1120)
        , ("shake.vec", "SHAKE-256(2000)", SHAKE256 2000)
        , ("skein.vec", "Skein-512(224)", Skein512 224 "")
        , ("skein.vec", "Skein-512(256)", Skein512 256 "")
        , ("skein.vec", "Skein-512(384)", Skein512 384 "")
        , ("skein.vec", "Skein-512(512)", Skein512 512 "")
        , ("skein.vec", "Skein-512(512,Test)", Skein512 512 "Test")
        , ("streebog.vec", "Streebog-256", Streebog256)
        , ("streebog.vec", "Streebog-512", Streebog512)
        , ("sm3.vec", "SM3", SM3)
        , ("whirlpool.vec", "Whirlpool", Whirlpool)
        ] $ \ (file, algoName, hashType) ->
            it (T.unpack $ T.validate algoName) $ do
                tvMap <- parseHashTestVector =<< "./third_party/botan/src/tests/data/hash/" `FS.join` file
                tvs <- unwrap' "ENOTFOUND" "no algo found" $ lookup algoName tvMap
                forM_ tvs $ \ (i, o) -> hash hashType i @?= o
