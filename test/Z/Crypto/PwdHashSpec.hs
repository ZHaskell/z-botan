{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.PwdHashSpec where

import Control.Monad
import Test.HUnit
import Test.Hspec (Spec, describe, it)
import Utils (parsePasswdHashTestVector)
import Z.Crypto.PwdHash
import qualified Z.Data.Text as T
import Z.Crypto.RNG (RNGType (SystemRNG), newRNG)

spec :: Spec
spec = describe "Crypto.PwdHash" $ do
    it "Bcrypt" $ do
        tvMap <- parsePasswdHashTestVector "./third_party/botan/src/tests/data/passhash/bcrypt.vec"
        forM_ tvMap $ \ (passwd, passhash) ->
            case mkPasswordMaybe =<< T.validateMaybe passwd of
                Just pwd -> do
                    rng <- newRNG SystemRNG
                    ret <- genBcrypt pwd rng 8
                    b <- validBcrypt pwd passhash
                    b @?= True
                _ -> return ()
