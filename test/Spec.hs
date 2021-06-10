-- file test/Spec.hs
#ifdef mingw32_HOST_OS
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Spec where
module Z.Crypto.HashSpec where

import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.IO.FileSystem    as FS
import qualified Z.Data.Text        as T
import           Z.Crypto.Hash
import           Utils

spec :: Spec
spec = describe "Crypto.Hash" $ do
    hash SHA256 "hello, world" @?= "09CA7E4EAA6E8AE9C7D261167129184883644D07DFBA7CBFBC4C8A2E08360D5B"

#else
{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
#end
