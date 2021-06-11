{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.Data.CBytes      as CB
import           Z.Crypto.MPI
import           Utils

main :: IO ()
main = hspec $ do
    describe "test without botan struct" $ do
        it "test" $ do
            (1 :: MPI) @?= (1 :: MPI)
