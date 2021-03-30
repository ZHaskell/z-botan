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
import           Z.Crypto.Cipher
import           Z.Crypto.Hash
import           Utils

spec :: Spec
spec = do
  describe "Crypto.Cipher.BlockCipher" $ do
    forM_
        [ ("aes", "aes.vec", "AES-128", AES128)
        , ("aes", "aes.vec", "AES-192", AES192)
        , ("aes", "aes.vec", "AES-256", AES256)
        , ("aria", "aria.vec", "ARIA-128", ARIA128)
        , ("aria", "aria.vec", "ARIA-192", ARIA192)
        , ("aria", "aria.vec", "ARIA-256", ARIA256)
        , ("blowfish", "blowfish.vec", "Blowfish", Blowfish)
        , ("camellia", "camellia.vec", "Camellia-128", Camellia128)
        , ("camellia", "camellia.vec", "Camellia-192", Camellia192)
        , ("camellia", "camellia.vec", "Camellia-256", Camellia256)
        , ("cascade", "cascade.vec", "Cascade(Serpent,Twofish)", Cascade Serpent Twofish)
        , ("cascade", "cascade.vec", "Cascade(Serpent,AES-256)", Cascade Serpent AES256)
        , ("cascade", "cascade.vec", "Cascade(Serpent,CAST-128)", Cascade Serpent CAST128)
        , ("cast128", "cast128.vec", "CAST-128", CAST128)
        , ("cast256", "cast256.vec", "CAST-256", CAST256)
        , ("des", "des.vec", "DES", DES)
        , ("idea", "idea.vec", "IDEA", IDEA)
        , ("kasumi", "kasumi.vec", "KASUMI", KASUMI)
        , ("lion", "lion.vec", "Lion(SHA-160,RC4,64)", Lion SHA160 RC4 64)
        , ("misty", "misty.vec", "MISTY1", MISTY1)
        , ("noekeon", "noekeon.vec", "Noekeon", Noekeon)
        , ("seed", "seed.vec", "SEED", SEED)
        , ("serpent", "serpent.vec", "Serpent", Serpent)
        , ("shacal2", "shacal2.vec", "SHACAL2", SHACAL2)
        -- dont support iterations
        -- , ("sm4", "sm4.vec", "SM4", SM4)
        -- dont support tweak
        -- , ("threefish", "threefish.vec", "Threefish-512", Threefish512)
        , ("twofish", "twofish.vec", "Twofish", Twofish)
        , ("xtea", "xtea.vec", "XTEA", XTEA)
        ] $ \ (label, file, algoName, cipherType) ->
            it label $ do
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
        [ ("cbc", "cbc.vec", "DES/CBC/NoPadding", CBC_NoPadding DES)
        , ("cbc", "cbc.vec", "CAST-128/CBC/PKCS7", CBC_PKCS7 CAST128)


        ] $ \ (label, file, algoName, cipherType) ->
            it label $ do
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
