{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.Data.CBytes      as CB
import           Z.Botan.FFI
import           Utils

main :: IO ()
main = hspec $ do
    describe "test without botan struct" $ do
        it "test" $ do
            msg <- CB.fromCString =<< botan_x509_cert_validation_status 1
            msg @?= "OCSP response accepted as affirming unrevoked status for certificate"
