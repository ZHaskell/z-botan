{-# LANGUAGE OverloadedStrings #-}
module Main where

import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.Data.CBytes      as CB
import           Z.Botan.Errno
import           Utils

main :: IO ()
main = hspec $ do
    describe "test without botan struct" $ do
        it "test" $ do
            e1 <- botanErrDesc (-1)
            e2 <- botanErrDesc (-1)
            e1 @?= e2
