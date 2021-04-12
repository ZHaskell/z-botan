{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Z.Crypto.KDFSpec where
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
import           Z.Crypto.KDF
import           Utils

spec :: Spec
spec = do
    describe "Crypto.KDF.KDF" $ do
        forM_
            [ ("hkdf.vec", "HKDF(HMAC(SHA-160))", HKDF (HMAC SHA160))
            , ("hkdf.vec", "HKDF(HMAC(SHA-256))", HKDF (HMAC SHA256))
            , ("hkdf.vec", "HKDF(HMAC(SHA-512))", HKDF (HMAC SHA512))
            , ("hkdf.vec", "HKDF-Extract(HMAC(SHA-160))", HKDF_Extract (HMAC SHA160))
            , ("hkdf.vec", "HKDF-Extract(HMAC(SHA-256))", HKDF_Extract (HMAC SHA256))
            , ("hkdf.vec", "HKDF-Extract(HMAC(SHA-512))", HKDF_Extract (HMAC SHA512))
            , ("hkdf.vec", "HKDF-Expand(HMAC(SHA-160))", HKDF_Expand (HMAC SHA160))
            , ("hkdf.vec", "HKDF-Expand(HMAC(SHA-256))", HKDF_Expand (HMAC SHA256))
            , ("hkdf.vec", "HKDF-Expand(HMAC(SHA-512))", HKDF_Expand (HMAC SHA512))
            , ("kdf1_iso18033.vec", "KDF1-18033(SHA-160)", KDF1_18033 SHA160)
            , ("kdf1_iso18033.vec", "KDF1-18033(SHA-256)", KDF1_18033 SHA256)
            , ("kdf1.vec", "KDF1(SHA-160)", KDF1 SHA160)
            , ("kdf2.vec", "KDF2(SHA-160)", KDF2 SHA160)
            , ("kdf2.vec", "KDF2(SHA-256)", KDF2 SHA256)
            , ("sp800_56a.vec", "SP800-56A(SHA-160)", SP800_56AHash SHA160)
            , ("sp800_56a.vec", "SP800-56A(SHA-224)", SP800_56AHash SHA224)
            , ("sp800_56a.vec", "SP800-56A(SHA-256)", SP800_56AHash SHA256)
            , ("sp800_56a.vec", "SP800-56A(SHA-384)", SP800_56AHash SHA384)
            , ("sp800_56a.vec", "SP800-56A(SHA-512)", SP800_56AHash SHA512)
            , ("sp800_56a.vec", "SP800-56A(HMAC(SHA-160))", SP800_56AMAC (HMAC SHA160))
            , ("sp800_56a.vec", "SP800-56A(HMAC(SHA-224))", SP800_56AMAC (HMAC SHA224))
            , ("sp800_56a.vec", "SP800-56A(HMAC(SHA-256))", SP800_56AMAC (HMAC SHA256))
            , ("sp800_56a.vec", "SP800-56A(HMAC(SHA-384))", SP800_56AMAC (HMAC SHA384))
            , ("sp800_56a.vec", "SP800-56A(HMAC(SHA-512))", SP800_56AMAC (HMAC SHA512))
            , ("sp800_56c.vec", "SP800-56C(HMAC(SHA-160))", SP800_56C (HMAC SHA160))
            , ("sp800_56c.vec", "SP800-56C(HMAC(SHA-256))", SP800_56C (HMAC SHA256))
            , ("sp800_56c.vec", "SP800-56C(HMAC(SHA-384))", SP800_56C (HMAC SHA384))
            , ("sp800_56c.vec", "SP800-56C(HMAC(SHA-512))", SP800_56C (HMAC SHA512))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(HMAC(SHA-160))", SP800_108_Counter (HMAC SHA160))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(HMAC(SHA-256))", SP800_108_Counter (HMAC SHA256))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(HMAC(SHA-384))", SP800_108_Counter (HMAC SHA384))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(HMAC(SHA-512))", SP800_108_Counter (HMAC SHA512))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(CMAC(AES-128))", SP800_108_Counter (CMAC AES128))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(CMAC(AES-192))", SP800_108_Counter (CMAC AES192))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(CMAC(AES-256))", SP800_108_Counter (CMAC AES256))
            , ("sp800_108_ctr.vec", "SP800-108-Counter(CMAC(TripleDES))", SP800_108_Counter (CMAC TripleDES))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(HMAC(SHA-160))", SP800_108_Feedback (HMAC SHA160))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(HMAC(SHA-256))", SP800_108_Feedback (HMAC SHA256))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(HMAC(SHA-384))", SP800_108_Feedback (HMAC SHA384))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(HMAC(SHA-512))", SP800_108_Feedback (HMAC SHA512))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(CMAC(AES-128))", SP800_108_Feedback (CMAC AES128))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(CMAC(AES-192))", SP800_108_Feedback (CMAC AES192))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(CMAC(AES-256))", SP800_108_Feedback (CMAC AES256))
            , ("sp800_108_fb.vec", "SP800-108-Feedback(CMAC(TripleDES))", SP800_108_Feedback (CMAC TripleDES))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(HMAC(SHA-160))", SP800_108_Pipeline (HMAC SHA160))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(HMAC(SHA-256))", SP800_108_Pipeline (HMAC SHA256))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(HMAC(SHA-384))", SP800_108_Pipeline (HMAC SHA384))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(HMAC(SHA-512))", SP800_108_Pipeline (HMAC SHA512))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(CMAC(AES-128))", SP800_108_Pipeline (CMAC AES128))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(CMAC(AES-192))", SP800_108_Pipeline (CMAC AES192))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(CMAC(AES-256))", SP800_108_Pipeline (CMAC AES256))
            , ("sp800_108_pipe.vec", "SP800-108-Pipeline(CMAC(TripleDES))", SP800_108_Pipeline (CMAC TripleDES))
            , ("tls_prf.vec", "TLS-PRF", TLS_PRF)
            , ("tls_prf.vec", "TLS-12-PRF(HMAC(SHA-224))", TLS_12_PRF (HMAC SHA224))
            , ("tls_prf.vec", "TLS-12-PRF(HMAC(SHA-256))", TLS_12_PRF (HMAC SHA256))
            , ("tls_prf.vec", "TLS-12-PRF(HMAC(SHA-384))", TLS_12_PRF (HMAC SHA384))
            , ("tls_prf.vec", "TLS-12-PRF(HMAC(SHA-512))", TLS_12_PRF (HMAC SHA512))
            -- dont support iterations
            -- , ("x942", "X9.42-PRF(KeyWrap.TripleDES)", ...)
            -- , ("x942", "X9.42-PRF(1.2.840.113549.1.9.16.3.7)", ...)
            ] $ \ (file, algoName, kdfType) ->
                it (T.unpack $ T.validate algoName) $ do
                    tvMap <- parseKDFTestVector =<< "./third_party/botan/src/tests/data/kdf/" `FS.join` file
                    tvs <- unwrap' "ENOTFOUND" "no algo founded" $ lookup algoName tvMap
                    forM_ tvs $ \ (salt, label, secret, o) -> do
                        o' <- kdf kdfType (V.length o) secret salt label
                        o' @?= o

    describe "Crypto.KDF.PBKDF" $ do
        forM_
            [ -- PBKDF1 is not recommanded and not supoorted
              -- ("pbkdf1.vec", "PBKDF1(SHA-160)", PBKDF1 SHA160)
              ("pbkdf2.vec", "PBKDF2(HMAC(SHA-160))", PBKDF2 (HMAC SHA160))
            , ("pbkdf2.vec", "PBKDF2(HMAC(SHA-256))", PBKDF2 (HMAC SHA256))
            , ("pbkdf2.vec", "PBKDF2(HMAC(SHA-384))", PBKDF2 (HMAC SHA384))
            , ("pbkdf2.vec", "PBKDF2(HMAC(SHA-512))", PBKDF2 (HMAC SHA512))
            , ("pbkdf2.vec", "PBKDF2(CMAC(Blowfish))", PBKDF2 (CMAC Blowfish))
            , ("pgp_s2k.vec", "OpenPGP-S2K(SHA-160)", OpenPGP_S2K SHA160)
            ] $ \ (file, algoName, pbkdfType) ->
                it (T.unpack $ T.validate algoName) $ do
                    tvMap <- parsePBKDFTestVector =<< "./third_party/botan/src/tests/data/pbkdf/" `FS.join` file
                    tvs <- unwrap' "ENOTFOUND" "no algo founded" $ lookup algoName tvMap
                    forM_ tvs $ \ (salt, iterations, passphrase, o) -> do
                        o' <- pbkdf (pbkdfType iterations) (V.length o) passphrase salt
                        o' @?= o
