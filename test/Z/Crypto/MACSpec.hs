{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.MACSpec where
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
import qualified Z.Data.Vector.FlatMap as Map
import           Z.Crypto.Cipher
import           Z.Crypto.Hash
import           Z.Crypto.MAC
import           Utils

spec :: Spec
spec = do
    describe "Crypto.MAC" $ do
        forM_
            [ ("cbcmac.vec", "CBC-MAC(DES)", CBC_MAC DES)
            , ("cbcmac.vec", "CBC-MAC(AES-128)", CBC_MAC AES128)
            , ("cmac.vec", "CMAC(AES-128)", CMAC AES128)
            , ("cmac.vec", "CMAC(AES-192)", CMAC AES192)
            , ("cmac.vec", "CMAC(AES-256)", CMAC AES256)
            , ("cmac.vec", "CMAC(Blowfish)", CMAC Blowfish)
            , ("cmac.vec", "CMAC(Threefish-512)", CMAC Threefish512)
            , ("gmac.vec", "GMAC(AES-128)", GMAC AES128)
            , ("gmac.vec", "GMAC(AES-192)", GMAC AES192)
            , ("gmac.vec", "GMAC(AES-256)", GMAC AES256)
            , ("hmac.vec", "HMAC(MD5)", HMAC MD5)
            , ("hmac.vec", "HMAC(SHA-160)", HMAC SHA160)
            , ("hmac.vec", "HMAC(RIPEMD-160)", HMAC RIPEMD160)
            , ("hmac.vec", "HMAC(SHA-224)", HMAC SHA224)
            , ("hmac.vec", "HMAC(SHA-256)", HMAC SHA256)
            , ("hmac.vec", "HMAC(SHA-384)", HMAC SHA384)
            , ("hmac.vec", "HMAC(SHA-512)", HMAC SHA512)
            , ("hmac.vec", "HMAC(SHA-512-256)", HMAC SHA512_256)
            , ("hmac.vec", "HMAC(SHA-3(224))", HMAC SHA3_224)
            , ("hmac.vec", "HMAC(SHA-3(256))", HMAC SHA3_256)
            , ("hmac.vec", "HMAC(SHA-3(384))", HMAC SHA3_384)
            , ("hmac.vec", "HMAC(SHA-3(512))", HMAC SHA3_512)
            , ("poly1305.vec", "Poly1305", Poly1305)
            , ("siphash.vec", "SipHash(2,4)", SipHash 2 4)
            , ("x919_mac.vec", "X9.19-MAC", X9'19_MAC)
            ] $ \ (file, algoName, macType) ->
                it (T.unpack $ T.validate algoName) $ do
                    tvMap <- parseMACTestVector =<< "./third_party/botan/src/tests/data/mac/" `FS.join` file
                    tvs <- unwrap' "ENOTFOUND" "no algo founded" $ lookup algoName tvMap
                    forM_ tvs $ \(miv, key0, i, o) -> case miv of
                        Just _  -> return ()  -- mac->start(nonce) is not supported yet.
                        Nothing -> do

                            key <- unsafeSecretFromBytes key0

                            m <- newMAC macType
                            setKeyMAC m key
                            updateMAC m i
                            o' <- finalMAC m
                            o' @?= ceBytes o

                            -- test clear
                            clearMAC m
                            setKeyMAC m key
                            updateMAC m "some discarded input"
                            clearMAC m
                            setKeyMAC m key
                            updateMAC m i
                            o'' <- finalMAC m
                            o'' @=? ceBytes o

                            -- test multiple update
                            let ilen = V.length i
                            when (ilen > 2) $ do
                                clearMAC m
                                setKeyMAC m key
                                updateMAC m $ V.slice 0 1 i
                                updateMAC m $ V.slice 1 (ilen - 2) i
                                updateMAC m $ V.slice (ilen - 1) 1 i
                                o''' <- finalMAC m
                                o''' @=? ceBytes o
