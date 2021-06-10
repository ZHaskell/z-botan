-- file test/Spec.hs
{-# LANGUAGE CPP #-}
#ifdef mingw32_HOST_OS

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Main where

import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.IO.FileSystem    as FS
import qualified Z.Data.Text        as T
import           Z.Crypto.Hash
import           Utils

main :: IO ()
main = hspec $
    describe "Crypto.Hash" $ do
        it "SHA256" $ print "test"

#else
{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
#endif
