{-# LANGUAGE OverloadedStrings #-}

module Z.Crypto.KeyWrapSpec where

import           Control.Monad
import           Test.HUnit
import           Test.Hspec
import           Utils
import           Z.Crypto.KeyWrap
import qualified Z.Data.Vector     as V
import qualified Z.Data.Vector.Hex as H
import qualified Z.IO.FileSystem   as FS

spec :: Spec
spec = describe "Crypto.KeyWrap" $ do
    it "RFC 3394" $ do
        tvMap <- parseKeyWrapVec "./third_party/botan/src/tests/data/keywrap/rfc3394.vec"
        forM_ tvMap $ \ (key, kek, o) -> do
            o' <- keyWrap key kek
            o' @?= o
