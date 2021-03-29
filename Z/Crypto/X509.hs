-- |
-- A certificate is a binding between some identifying information (called a subject) and a public key.
-- This binding is asserted by a signature on the certificate,
-- which is placed there by some authority (the issuer) that at least claims that it knows the subject named in the certificate really “owns” the private key corresponding to the public key in the certificate.
--
-- The major certificate format in use today is X.509v3, used for instance in the Transport Layer Security (TLS) protocol. A X.509 certificate is represented by the type X509_Certificate.
--
-- It will occasionally happen that a certificate must be revoked before its expiration date.
-- Examples of this happening include the private key being compromised, or the user to which it has been assigned leaving an organization.
-- Certificate revocation lists are an answer to this problem (though online certificate validation techniques are starting to become somewhat more popular).
-- Every once in a while the CA will release a new CRL, listing all certificates that have been revoked.
-- Also included is various pieces of information like what time a particular certificate was revoked, and for what reason.
-- In most systems, it is wise to support some form of certificate revocation, and CRLs handle this easily.
module Z.Crypto.X509 where

import Foreign (Word32, Word64)
import Z.Botan.Exception (throwBotanIfMinus_)
import Z.Botan.FFI
  ( BotanStruct,
    botan_pubkey_destroy,
    botan_x509_cert_allowed_usage,
    botan_x509_cert_destroy,
    botan_x509_cert_dup,
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
    botan_x509_cert_validation_status,
    botan_x509_crl_destroy,
    botan_x509_crl_load_file,
    botan_x509_is_revoked,
    hs_botan_x509_cert_load,
    hs_botan_x509_cert_verify,
    hs_botan_x509_cert_verify_with_crl,
    hs_botan_x509_crl_load,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.Hash (HashType, hashTypeToCBytes)
import Z.Crypto.PubKey (PubKey (..), maxFingerPrintSize)
import Z.Data.CBytes (CBytes, CString, fromBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign
  ( CInt,
    allocPrimUnsafe,
    allocPrimVectorUnsafe,
    withPrimVectorUnsafe,
  )

------------------------
-- X.509 Certificates --
------------------------

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

{-
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
-}

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
  | CRLSign
  | EncipherOnly
  | DecipherOnly

x509KeyConstraintToWord32 :: X509CertKeyConstraint -> Word32 -- unsigned int key_usage
x509KeyConstraintToWord32 = \case
  NoConstraints -> 0
  DigitalSignatrue -> 32768
  NonRepudiation -> 16384
  KeyEncipherment -> 8192
  DataEncipherment -> 4096
  KeyAgreement -> 2048
  KeyCertSign -> 1024
  CRLSign -> 512
  EncipherOnly -> 256
  DecipherOnly -> 128

type X509CertUsage = (X509Cert, X509CertKeyConstraint)

x509CertUsage :: X509Cert -> X509CertKeyConstraint -> IO ()
x509CertUsage (X509Cert cert) usage = do
  withBotanStruct cert $ \cert' ->
    throwBotanIfMinus_ $ botan_x509_cert_allowed_usage cert' (x509KeyConstraintToWord32 usage)

-- | Return a (statically allocated) CString associated with the verification result.
readX509CertValidateStatus :: CInt -> CString
readX509CertValidateStatus = botan_x509_cert_validation_status -- TODO: maybe unsafeDupablePerformIO

-- | Verify a certificate. Returns (Just True) if validation was successful, (Just False) if unsuccessful, or Nothing on error.
verifyX509Cert ::
  -- | The certificate to be verified.
  X509Cert ->
  -- | Intermediate certificates, set to NULL if not needed.
  V.Bytes ->
  -- | Trusted certificates, set to NULL if not needed.
  V.Bytes ->
  -- | The trusted path which refers to a directory where one or more trusted CA certificates are stored. It may be NULL if not needed.
  CBytes ->
  -- | Set required strength to indicate the minimum key and hash strength that is allowed.
  Int ->
  -- | Hostname.
  CBytes ->
  -- | Set reference time to be the time which the certificate chain is validated against. Use zero to use the current system clock.
  Word64 ->
  IO (Maybe Bool) -- TODO: maybe Bool, [X509Cert]
verifyX509Cert (X509Cert cert) intermediates trusted path strength hostname refTime = do
  withBotanStruct cert $ \cert' ->
    withPrimVectorUnsafe intermediates $ \intermediates' intermediatesOff intermediatesLen ->
      withPrimVectorUnsafe trusted $ \trusted' trustedOff trustedLen ->
        withCBytesUnsafe path $ \path' ->
          withCBytesUnsafe hostname $ \hostname' -> do
            (a, _) <- allocPrimUnsafe @CInt $ \ret ->
              throwBotanIfMinus_ $ hs_botan_x509_cert_verify ret cert' intermediates' intermediatesOff intermediatesLen trusted' trustedOff trustedLen path' strength hostname' refTime
            if a == 0
              then return (Just True)
              else if a == 1 then return (Just False) else return Nothing

-- | Certificate path validation supporting Certificate Revocation Lists.
-- Verify a certificate. Returns (Just True) if validation was successful, (Just False) if unsuccessful, or Nothing on error.
verifyX509CertCRL ::
  -- | The certificate to be verified.
  X509Cert ->
  -- | Intermediate certificates, set to NULL if not needed.
  V.Bytes ->
  -- | Trusted certificates, set to NULL if not needed.
  V.Bytes ->
  -- | Certificate Revocation Lists, set to NULL if not needed.
  V.Bytes ->
  -- | The trusted path which refers to a directory where one or more trusted CA certificates are stored. It may be NULL if not needed.
  CBytes ->
  -- | Set required strength to indicate the minimum key and hash strength that is allowed.
  Int ->
  -- | Hostname.
  CBytes ->
  -- | Set reference time to be the time which the certificate chain is validated against. Use zero to use the current system clock.
  Word64 ->
  IO (Maybe Bool)
verifyX509CertCRL (X509Cert cert) intermediates trusted crls path strength hostname refTime = do
  withBotanStruct cert $ \cert' ->
    withPrimVectorUnsafe intermediates $ \intermediates' intermediatesOff intermediatesLen ->
      withPrimVectorUnsafe trusted $ \trusted' trustedOff trustedLen ->
        withPrimVectorUnsafe crls $ \crls' crlsOff crlsLen ->
          withCBytesUnsafe path $ \path' ->
            withCBytesUnsafe hostname $ \hostname' -> do
              (a, _) <- allocPrimUnsafe @CInt $ \ret ->
                throwBotanIfMinus_ $ hs_botan_x509_cert_verify_with_crl ret cert' intermediates' intermediatesOff intermediatesLen trusted' trustedOff trustedLen crls' crlsOff crlsLen path' strength hostname' refTime
              if a == 0
                then return (Just True)
                else if a == 1 then return (Just False) else return Nothing

----------------------------------------
-- X.509 Certificate Revocation Lists --
----------------------------------------

-- | An opaque newtype wrapper for an X.509 Certificate Revocation Lists.
newtype X509CRL = X509CRL BotanStruct

-- | Load a CRL from the DER or PEM representation.
loadX509CRL :: V.Bytes -> IO X509CRL
loadX509CRL src = do
  withPrimVectorUnsafe src $ \src' off len ->
    X509CRL <$> newBotanStruct (\ret -> hs_botan_x509_crl_load ret src' off len) botan_x509_crl_destroy

-- | Load a CRL from a file.
loadX509CRLFile :: CBytes -> IO X509CRL
loadX509CRLFile src = do
  withCBytesUnsafe src $ \src' ->
    X509CRL <$> newBotanStruct (`botan_x509_crl_load_file` src') botan_x509_cert_destroy

-- | Check whether a given crl contains a given cert. Return True when the certificate is revoked, False otherwise.
isRevokedX509CRL :: X509CRL -> X509Cert -> IO (Maybe Bool) -- TODO: maybe Bool
isRevokedX509CRL (X509CRL xs) (X509Cert cert) =
  withBotanStruct xs $ \xs' ->
    withBotanStruct cert $ \cert' -> do
      ret <- botan_x509_is_revoked xs' cert'
      if ret == 0
        then return (Just True)
        else if ret == -1 then return (Just False) else return Nothing
