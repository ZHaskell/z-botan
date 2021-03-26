-- |
-- A certificate is a binding between some identifying information (called a subject) and a public key.
-- This binding is asserted by a signature on the certificate,
-- which is placed there by some authority (the issuer) that at least claims that it knows the subject named in the certificate really “owns” the private key corresponding to the public key in the certificate.
--
-- The major certificate format in use today is X.509v3, used for instance in the Transport Layer Security (TLS) protocol. A X.509 certificate is represented by the type X509_Certificate.
module Z.Crypto.X509 where

import Foreign (Word32, Word64)
import Z.Botan.Exception (throwBotanIfMinus_)
import Z.Botan.FFI
  ( BotanStruct,
    botan_pubkey_destroy,
    botan_x509_cert_destroy,
    botan_x509_cert_dup,
    botan_x509_cert_gen_selfsigned,
    botan_x509_cert_get_authority_key_id,
    botan_x509_cert_get_fingerprint,
    botan_x509_cert_get_issuer_dn,
    botan_x509_cert_get_public_key,
    botan_x509_cert_get_public_key_bits,
    botan_x509_cert_get_serial_number,
    botan_x509_cert_get_subject_dn,
    botan_x509_cert_get_subject_key_id,
    botan_x509_cert_get_time_expires,
    botan_x509_cert_get_time_starts,
    botan_x509_cert_load_file,
    botan_x509_cert_not_after,
    botan_x509_cert_not_before,
    botan_x509_cert_to_string,
    hs_botan_x509_cert_load,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.Hash (HashType, hashTypeToCBytes)
import Z.Crypto.PubKey (PrivKey (..), PubKey (..), maxFingerPrintSize)
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

-- | Return the finger print of the certificate.
readX509CertFingerPrint :: X509Cert -> HashType -> IO V.Bytes
readX509CertFingerPrint (X509Cert cert) hty = do
  withBotanStruct cert $ \cert' ->
    let hty' = hashTypeToCBytes hty
     in withCBytesUnsafe hty' $ \hty'' -> do
          (a, _) <- allocPrimVectorUnsafe maxFingerPrintSize $ \ret -> do
            (a', _) <- allocPrimUnsafe @Int $ \len ->
              throwBotanIfMinus_ $ botan_x509_cert_get_fingerprint cert' hty'' ret len
            pure a'
          return a

maxX509ReadSize :: Int
maxX509ReadSize = 64

-- | Return the serial number of the certificate.
readX509CertSerial :: X509Cert -> IO V.Bytes
readX509CertSerial (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
      (a', _) <- allocPrimUnsafe @Int $ \len ->
        throwBotanIfMinus_ $ botan_x509_cert_get_serial_number cert' ret len
      pure a'
    return a

-- | Return the authority key ID set in the certificate, which may be empty.
readX509CertIDAuthority :: X509Cert -> IO V.Bytes
readX509CertIDAuthority (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
      (a', _) <- allocPrimUnsafe @Int $ \len ->
        throwBotanIfMinus_ $ botan_x509_cert_get_authority_key_id cert' ret len
      pure a'
    return a

-- | Return the subject key ID set in the certificate, which may be empty.
readX509CertIDSubject :: X509Cert -> IO V.Bytes
readX509CertIDSubject (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
      (a', _) <- allocPrimUnsafe @Int $ \len ->
        throwBotanIfMinus_ $ botan_x509_cert_get_subject_key_id cert' ret len
      pure a'
    return a

-- | Get the serialized representation of the public key included in this certificate.
readX509CertPubBits :: X509Cert -> IO V.Bytes
readX509CertPubBits (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
      (a', _) <- allocPrimUnsafe @Int $ \len ->
        throwBotanIfMinus_ $ botan_x509_cert_get_public_key_bits cert' ret len
      pure a'
    return a

-- | Get the public key included in this certificate.
readX509CertPub :: X509Cert -> IO PubKey
readX509CertPub (X509Cert cert) = do
  withBotanStruct cert $ \cert' ->
    PubKey <$> newBotanStruct (cert' `botan_x509_cert_get_public_key`) botan_pubkey_destroy

-- | Get a value from the issuer DN field.
readX509CertDNIssuer ::
  X509Cert ->
  -- | key
  CBytes ->
  -- | index
  Int ->
  IO V.Bytes
readX509CertDNIssuer (X509Cert cert) key ix = do
  withBotanStruct cert $ \cert' ->
    withCBytesUnsafe key $ \key' -> do
      (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
        (a', _) <- allocPrimUnsafe @Int $ \len ->
          throwBotanIfMinus_ $ botan_x509_cert_get_issuer_dn cert' key' ix ret len
        pure a'
      return a

-- | Get a value from the subject DN field.
readX509CertDNSubject ::
  X509Cert ->
  -- | key
  CBytes ->
  -- | index
  Int ->
  IO V.Bytes
readX509CertDNSubject (X509Cert cert) key ix = do
  withBotanStruct cert $ \cert' ->
    withCBytesUnsafe key $ \key' -> do
      (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
        (a', _) <- allocPrimUnsafe @Int $ \len ->
          throwBotanIfMinus_ $ botan_x509_cert_get_subject_dn cert' key' ix ret len
        pure a'
      return a

-- | Format the certificate as a free-form string (CBytes).
x509CertToCBytes :: X509Cert -> IO CBytes
x509CertToCBytes (X509Cert cert) = do
  withBotanStruct cert $ \cert' -> do
    (a, _) <- allocPrimVectorUnsafe maxX509ReadSize $ \ret -> do
      (a', _) <- allocPrimUnsafe @Int $ \len ->
        throwBotanIfMinus_ $ botan_x509_cert_to_string cert' ret len
      pure a'
    return $ fromBytes a

-- | Certificate key usage constraints.
data X509CertKeyConstraint
  = NoConstraints
  | DigitalSignatrue
  | NonRepudiation
  | KeyEncipherment
  | DataEncipherment
  | KeyAgreement
  | KeyCertSign
  | CrlSign
  | EncipherOnly
  | DecipherOnly

constraintToWord32 :: X509CertKeyConstraint -> Word32 -- unsigned int key_usage
constraintToWord32 = \case
  NoConstraints -> 0
  DigitalSignatrue -> 32768
  NonRepudiation -> 16384
  KeyEncipherment -> 8192
  DataEncipherment -> 4096
  KeyAgreement -> 2048
  KeyCertSign -> 1024
  CrlSign -> 512
  EncipherOnly -> 256
  DecipherOnly -> 128

type X509CertUsage = (X509Cert, X509CertKeyConstraint)
