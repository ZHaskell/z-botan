{-# LANGUAGE OverloadedStrings #-}

module Z.Crypto.KDFSpec where

import Data.Foldable (forM_)
import Test.HUnit ((@=?))
import Test.Hspec (Spec, describe, it)
import Utils (parseKDFVec)
import Z.Crypto.Hash (HashType (SHA160))
import Z.Crypto.KDF (KDFType (HKDF), kdf)
import Z.IO (unwrap')
import Z.IO.FileSystem as FS (join)

maxKDFSize :: Int
maxKDFSize = 64

spec :: Spec
spec = describe "Crypto.KDF" $ do
  forM_ [("hkdf", "hkdf.vec", "HKDF(HMAC(SHA-160))", HKDF SHA160)] $ \(label', file, algoName, kdfType) ->
    it label' $ do
      tvMap <- parseKDFVec =<< "./third_party/botan/src/tests/data/hash/" `FS.join` file
      tvs <- unwrap' "ENOTFOUND" "no algo found" $ lookup algoName tvMap
      forM_ tvs $ \(salt, label, secret, output) -> do
        res <- kdf kdfType maxKDFSize secret salt label
        res @=? output
