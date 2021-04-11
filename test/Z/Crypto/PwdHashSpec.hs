{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.PwdHashSpec where

import Control.Monad (forM_)
import Test.HUnit
import Test.Hspec (Spec, describe, it)
import Utils (parsePasswdHashTestVector)
import Z.Crypto.PwdHash
import Z.Crypto.RNG (RNGType (SystemRNG), newRNG)

spec :: Spec
spec = describe "Crypto.PwdHash" $ do
    it "Bcrypt" $ do
        tvMap <- parsePasswdHashTestVector "./third_party/botan/src/tests/data/passhash/bcrypt.vec"
        forM_ tvMap $ \ (passwd, passhash) -> do
            rng <- newRNG SystemRNG
            ret <- genBcrypt passwd rng 8
            b <- validBcrypt passwd passhash
            b @?= True
