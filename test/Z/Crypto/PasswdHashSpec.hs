{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.PasswdHashSpec where

import Control.Monad (forM_)
import Test.HUnit ((@=?))
import Test.Hspec (Spec, describe, it)
import Utils' (parsePasswdHashVec)
import Z.Crypto.PasswdHash (newBcrypt)
import Z.Crypto.RNG (RNGType (SystemRNG), newRNG)

spec :: Spec
spec = describe "Crypto.PasswdHash" $ do
  it "Bcrypt" $ do
    tvMap <- parsePasswdHashVec "./third_party/botan/src/tests/data/passhash/bcrypt.vec"
    forM_ tvMap $ \(passwd, passhash) -> do
      rng <- newRNG SystemRNG
      ret <- newBcrypt passwd rng 8
      ret @=? passhash
