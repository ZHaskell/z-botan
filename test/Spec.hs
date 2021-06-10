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
import           Z.Crypto.Cipher
import           Z.Crypto.Hash
import           Z.Crypto.MPI
import           Utils

main :: IO ()
main = hspec $ do
    describe "Crypto.Hash" $ do
        forM_
            [ ("aes.vec", "AES-128", AES128)
            , ("aes.vec", "AES-192", AES192)
            , ("aes.vec", "AES-256", AES256)
            , ("aria.vec", "ARIA-128", ARIA128)
            , ("aria.vec", "ARIA-192", ARIA192)
            , ("aria.vec", "ARIA-256", ARIA256)
            , ("blowfish.vec", "Blowfish", Blowfish)
            , ("camellia.vec", "Camellia-128", Camellia128)
            , ("camellia.vec", "Camellia-192", Camellia192)
            , ("camellia.vec", "Camellia-256", Camellia256)
            , ("cascade.vec", "Cascade(Serpent,Twofish)", Cascade Serpent Twofish)
            , ("cascade.vec", "Cascade(Serpent,AES-256)", Cascade Serpent AES256)
            , ("cascade.vec", "Cascade(Serpent,CAST-128)", Cascade Serpent CAST128)
            , ("cast128.vec", "CAST-128", CAST128)
            , ("cast256.vec", "CAST-256", CAST256)
            , ("des.vec", "DES", DES)
            , ("idea.vec", "IDEA", IDEA)
            , ("kasumi.vec", "KASUMI", KASUMI)
            , ("lion.vec", "Lion(SHA-160,RC4,64)", Lion SHA160 RC4 64)
            , ("misty.vec", "MISTY1", MISTY1)
            , ("noekeon.vec", "Noekeon", Noekeon)
            , ("seed.vec", "SEED", SEED)
            , ("serpent.vec", "Serpent", Serpent)
            , ("shacal2.vec", "SHACAL2", SHACAL2)
            -- dont support iterations
            -- , ("sm4.vec", "SM4", SM4)
            -- dont support tweak
            -- , ("threefish.vec", "Threefish-512", Threefish512)
            , ("twofish.vec", "Twofish", Twofish)
            , ("xtea.vec", "XTEA", XTEA)
            ] $ \ (file, algoName, cipherType) ->
                it (T.unpack $ T.validate algoName) $ do
                    tvMap <- parseBlockCipherTestVector =<< "./third_party/botan/src/tests/data/block/" `FS.join` file
                    tvs <- unwrap' "ENOTFOUND" "no algo founded" $ lookup algoName tvMap
                    forM_ tvs $ \ (key0, i, o) -> do
                        print (key0, i, o)

    describe "Crypto.Hash" $ do
        it "MPI" $ do
            let p1 = (3 :: MPI)
                p2 = (4 :: MPI)
            p1 @?= p2

#else
{-# OPTIONS_GHC -F -pgmF hspec-discover #-}
#endif
