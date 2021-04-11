{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.CipherSpec where
import           Control.Monad
import           Test.Hspec
import           Test.HUnit
import           Z.IO
import qualified Z.IO.FileSystem as FS
import           Z.Data.ASCII
import           Z.Data.Vector.Hex
import qualified Z.Data.Parser      as P
import qualified Z.Data.Vector      as V
import qualified Z.Data.Text        as T
import           Z.Crypto.Cipher
import           Z.Crypto.Hash
import           Utils

spec :: Spec
spec = do
    describe "Crypto.Cipher.BlockCipher" $ do
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
                    forM_ tvs $ \ (key, i, o) -> do
                        c <- newBlockCipher cipherType
                        setBlockCipherKey c key
                        o' <- encryptBlocks c i (V.length i `quot` blockCipherSize c)
                        o' @=? o
                        i' <- decryptBlocks c o (V.length o `quot` blockCipherSize c)
                        i' @=? i

    describe "Crypto.Cipher.CipherMode" $ do
        forM_
            [ ("cbc.vec", "DES/CBC/NoPadding", CBC_NoPadding DES)
            , ("cbc.vec", "CAST-128/CBC/PKCS7", CBC_PKCS7 CAST128)
            , ("cbc.vec", "DES/CBC/PKCS7", CBC_PKCS7 DES)
            , ("cbc.vec", "TripleDES/CBC/NoPadding", CBC_NoPadding TripleDES)
            , ("cbc.vec", "TripleDES/CBC/PKCS7", CBC_PKCS7 TripleDES)
            , ("cbc.vec", "Blowfish/CBC/NoPadding", CBC_NoPadding Blowfish)
            , ("cbc.vec", "Noekeon/CBC/PKCS7", CBC_PKCS7 Noekeon)
            , ("cbc.vec", "DES/CBC/OneAndZeros", CBC_OneAndZeros DES)
            , ("cbc.vec", "DES/CBC/CTS", CBC_CTS DES)
            , ("cbc.vec", "AES-128/CBC/PKCS7", CBC_PKCS7 AES128)
            , ("cbc.vec", "AES-128/CBC/NoPadding", CBC_NoPadding AES128)
            , ("cbc.vec", "AES-192/CBC/NoPadding", CBC_NoPadding AES192)
            , ("cbc.vec", "AES-256/CBC/NoPadding", CBC_NoPadding AES256)
            , ("cbc.vec", "AES-128/CBC/CTS", CBC_CTS AES128)
            , ("cbc.vec", "ARIA-256/CBC/NoPadding", CBC_NoPadding ARIA256)
            , ("cfb.vec", "DES/CFB", CFB DES 0)
            , ("cfb.vec", "DES/CFB(32)", CFB DES 32)
            , ("cfb.vec", "DES/CFB(16)", CFB DES 16)
            , ("cfb.vec", "DES/CFB(8)", CFB DES 8)
            , ("cfb.vec", "TripleDES/CFB", CFB TripleDES 0)
            , ("cfb.vec", "TripleDES/CFB(8)", CFB TripleDES 8)
            , ("cfb.vec", "AES-128/CFB(8)", CFB AES128 8)
            , ("cfb.vec", "AES-192/CFB(8)", CFB AES192 8)
            , ("cfb.vec", "AES-256/CFB(8)", CFB AES256 8)
            , ("cfb.vec", "AES-128/CFB", CFB AES128 0)
            , ("cfb.vec", "AES-192/CFB", CFB AES192 0)
            , ("cfb.vec", "AES-256/CFB", CFB AES256 0)
            , ("xts.vec", "AES-128/XTS", XTS AES128)
            , ("xts.vec", "AES-256/XTS", XTS AES256)
            , ("xts.vec", "Twofish/XTS", XTS Twofish)
            , ("xts.vec", "Serpent/XTS", XTS Serpent)
            , ("xts.vec", "TripleDES/XTS", XTS TripleDES)
            , ("xts.vec", "SHACAL2/XTS", XTS SHACAL2)
            , ("xts.vec", "Threefish-512/XTS", XTS Threefish512)
            ] $ \ (file, algoName, cipherType) ->
                it (T.unpack $ T.validate algoName) $ do
                    tvMap <- parseCipherModeTestVector =<< "./third_party/botan/src/tests/data/modes/" `FS.join` file
                    tvs <- unwrap' "ENOTFOUND" "no algo founded" $ lookup algoName tvMap
                    forM_ tvs $ \ (key, nonce, i, o) -> do

                        c <- newCipher cipherType CipherEncrypt
                        setCipherKey c key
                        startCipher c nonce

                        d <- newCipher cipherType CipherDecrypt
                        setCipherKey d key
                        startCipher d nonce

                        o' <- finishCipher c i
                        o' @=? o
                        i' <- finishCipher d o
                        i' @=? i

    describe "Crypto.Cipher.StreamCipher(I)" $ do
        forM_
            [ ("ctr.vec", "CTR-BE(DES)", CTR_BE DES)
            , ("ctr.vec", "CTR-BE(AES-128)", CTR_BE AES128)
            ] $ \ (file, algoName, cipherType) ->
                it (T.unpack $ T.validate algoName) $ do
                    tvMap <- parseCipherModeTestVector =<< "./third_party/botan/src/tests/data/modes/" `FS.join` file
                    tvs <- unwrap' "ENOTFOUND" "no algo founded" $ lookup algoName tvMap
                    forM_ tvs $ \ (key, nonce, i, o) -> do

                        c <- newStreamCipher cipherType CipherEncrypt
                        setCipherKey c key
                        startCipher c nonce

                        d <- newStreamCipher cipherType CipherDecrypt
                        setCipherKey d key
                        startCipher d nonce

                        o' <- finishCipher c i
                        o' @=? o
                        i' <- finishCipher d o
                        i' @=? i
