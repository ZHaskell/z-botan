-- |
-- A certificate is a binding between some identifying information (called a subject) and a public key.
-- This binding is asserted by a signature on the certificate,
-- which is placed there by some authority (the issuer) that at least claims that it knows the subject named in the certificate really “owns” the private key corresponding to the public key in the certificate.
--
-- The major certificate format in use today is X.509v3, used for instance in the Transport Layer Security (TLS) protocol. A X.509 certificate is represented by the type X509_Certificate.
module Z.Crypto.X509 where

import Z.Botan.FFI
import Z.Crypto.PubKey
import Z.Crypto.RNG
import Z.Data.CBytes
import qualified Z.Data.Vector as V
import Z.Foreign

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
