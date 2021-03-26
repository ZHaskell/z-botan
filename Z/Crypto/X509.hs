-- |
-- A certificate is a binding between some identifying information (called a subject) and a public key.
-- This binding is asserted by a signature on the certificate,
-- which is placed there by some authority (the issuer) that at least claims that it knows the subject named in the certificate really “owns” the private key corresponding to the public key in the certificate.
--
-- The major certificate format in use today is X.509v3, used for instance in the Transport Layer Security (TLS) protocol. A X.509 certificate is represented by the type X509_Certificate.
module Z.Crypto.X509 where

import Data.Word (Word64)
import Z.Botan.Exception (throwBotanIfMinus_)
import Z.Botan.FFI
  ( BotanStruct,
    botan_x509_cert_destroy,
    botan_x509_cert_dup,
    botan_x509_cert_gen_selfsigned,
    botan_x509_cert_get_time_expires,
    botan_x509_cert_get_time_starts,
    botan_x509_cert_load_file,
    botan_x509_cert_not_after,
    botan_x509_cert_not_before,
    hs_botan_x509_cert_load,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.Hash (HashType)
import Z.Crypto.PubKey (PrivKey (..))
import Z.Crypto.RNG (RNG, withRNG)
import Z.Data.CBytes (CBytes, fromBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign
  ( allocPrimUnsafe,
    allocPrimVectorUnsafe,
    withPrimVectorUnsafe,
  )

-- | An opaque newtype wrapper for an X.509 certificate.
newtype X509Cert = X509Cert BotanStruct

-- | Load a certificate from the DER or PEM representation.
loadX509Cert :: V.Bytes -> IO X509Cert
loadX509Cert cert = do
  withPrimVectorUnsafe cert $ \cert' off len ->
    X509Cert <$> newBotanStruct (\ret -> hs_botan_x509_cert_load ret cert' off len) botan_x509_cert_destroy

-- | Load a certificate from a file.
loadX509CertFile :: CBytes -> IO X509Cert
loadX509CertFile name = do
  withCBytesUnsafe name $ \name' ->
    X509Cert <$> newBotanStruct (`botan_x509_cert_load_file` name') botan_x509_cert_destroy

-- | Create a new object that refers to the same certificate.
dupX509Cert :: X509Cert -> IO X509Cert
dupX509Cert (X509Cert cert) = do
  withBotanStruct cert $ \cert' ->
    X509Cert <$> newBotanStruct (`botan_x509_cert_dup` cert') botan_x509_cert_destroy

-- | Create a new self-signed X.509 certificate.
-- Generating a new self-signed certificate can often be useful, for example when setting up a new root CA, or for use in specialized protocols.
newX509CertSelfsigned ::
  -- | the private key you wish to use (the public key, used in the certificate itself is extracted from the private key)
  PrivKey ->
  RNG ->
  -- | common name
  CBytes ->
  -- | org name
  CBytes ->
  IO X509Cert
newX509CertSelfsigned (PrivKey key) rng common org = do
  withBotanStruct key $ \key' ->
    withRNG rng $ \rng' ->
      withCBytesUnsafe common $ \common' ->
        withCBytesUnsafe org $ \org' ->
          X509Cert <$> newBotanStruct (\ret -> botan_x509_cert_gen_selfsigned ret key' rng' common' org') botan_x509_cert_destroy

maxTDSize :: Int
maxTDSize = 16

-- | Return the time the certificate becomes valid, as a CBytes in form “YYYYMMDDHHMMSSZ” where Z is a literal character reflecting that this time is relative to UTC.
readX509CertStart :: X509Cert -> IO CBytes
readX509CertStart (X509Cert cert) = do
  (a, _) <- allocPrimVectorUnsafe maxTDSize $ \td -> do
    (a', _) <- allocPrimUnsafe @Int $ \len ->
      withBotanStruct cert $ \cert' ->
        throwBotanIfMinus_ $ botan_x509_cert_get_time_starts cert' td len
    pure a'
  return $ fromBytes a

-- | Return the time the certificate expires, as a CBytes in form “YYYYMMDDHHMMSSZ” where Z is a literal character reflecting that this time is relative to UTC.
readX509CertExpire :: X509Cert -> IO CBytes
readX509CertExpire (X509Cert cert) = do
  (a, _) <- allocPrimVectorUnsafe maxTDSize $ \td -> do
    (a', _) <- allocPrimUnsafe @Int $ \len ->
      withBotanStruct cert $ \cert' ->
        throwBotanIfMinus_ $ botan_x509_cert_get_time_expires cert' td len
    pure a'
  return (fromBytes a)

-- | Return the time the certificate becomes valid, as seconds since epoch.
readX509CertNotBefore :: X509Cert -> IO Word64
readX509CertNotBefore (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimUnsafe @Word64 $ \time ->
      botan_x509_cert_not_before cert' time
    return a

-- | Return the time the certificate expires, as seconds since epoch.
readX509CertNotAfter :: X509Cert -> IO Word64
readX509CertNotAfter (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimUnsafe @Word64 $ \time ->
      botan_x509_cert_not_after cert' time
    return a

readX509CertFingerPrint :: X509Cert -> IO HashType
readX509CertFingerPrint = undefined
