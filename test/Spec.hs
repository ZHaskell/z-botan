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

        it "SHA256'" $ do
            hash SHA256 "hello, world" @?= "09CA7E4EAA6E8AE9C7D261167129184883644D07DFBA7CBFBC4C8A2E08360D5B"

#else
{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
#endif
