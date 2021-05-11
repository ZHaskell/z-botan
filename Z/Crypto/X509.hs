{-|
Module      : Z.Crypto.X509
Description : X.509 Certificates and CRLs
Copyright   : Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

X.509 Certificates read, write and verification.

-}
module Z.Crypto.X509 (
  -- * X509 Certificates
    Cert, withCert
  , loadCert, loadCertFile, dupCert
  -- * read X509 field
  , certStart, certExpire
  , certStart', certExpire'
  , certStartText, certExpireText
  , certFingerPrint
  , certSerial
  , certIDAuthority
  , certIDSubject
  , certPubBits
  , certPubKey
  , certDNIssuer
  , certDNSubject
  , certToText
  , certUsage
  -- * verify certificate
  , verifyCert
  , verifyCertCRL
  , verifyCertCRL'
  -- * CRL
  , CRL
  , withCRL, loadCRL, loadCRLFile, isRevokedX509
  -- * CertStore
  , CertStore
  , withCertStore
  , loadCertStoreFile
  -- * constants
  , KeyUsageConstraint
  , pattern NO_CONSTRAINTS
  , pattern DIGITAL_SIGNATURE
  , pattern NON_REPUDIATION
  , pattern KEY_ENCIPHERMENT
  , pattern DATA_ENCIPHERMENT
  , pattern KEY_AGREEMENT
  , pattern KEY_CERT_SIGN
  , pattern CRL_SIGN
  , pattern ENCIPHER_ONLY
  , pattern DECIPHER_ONLY
  ) where

import           Data.Time.Clock.System (SystemTime (..))
import           Data.Word
import           GHC.Generics
import           Z.Botan.Exception
import           Z.Botan.FFI
import           Z.Crypto.Hash          (HashType, hashTypeToCBytes)
import           Z.Crypto.PubKey        (PubKey (..))
import qualified Z.Data.Text            as T
import qualified Z.Data.Text.Base       as T
import qualified Z.Data.Vector          as V
import qualified Z.Data.Vector.Extra    as V
import           Z.Data.CBytes          (CBytes)
import qualified Z.Data.CBytes          as CB
import           Z.Foreign
import           Z.Foreign.CPtr
import           System.IO.Unsafe

------------------------
-- X.509 Certificates --
------------------------

-- | An opaque newtype wrapper for an X.509 certificate.
--
-- A certificate is a binding between some identifying information (called a subject) and a public key.
-- This binding is asserted by a signature on the certificate, which is placed there by some authority (the issuer) that at least claims that it knows the subject named in the certificate really “owns” the private key corresponding to the public key in the certificate.
--
-- The major certificate format in use today is X.509v3, used for instance in the Transport Layer Security (TLS) protocol. A X.509 certificate is represented by the type 'Cert'.
newtype Cert = Cert { certStruct :: BotanStruct }
    deriving (Show, Generic)
    deriving anyclass T.Print

withCert :: HasCallStack => Cert -> (BotanStructT -> IO r) -> IO r
withCert (Cert cert) = withBotanStruct cert

-- | Load a certificate from the DER or PEM representation.
loadCert :: HasCallStack => V.Bytes -> IO Cert
loadCert cert = do
    withPrimVectorUnsafe cert $ \ cert' off len ->
        Cert <$> newBotanStruct
            (\ ret -> hs_botan_x509_cert_load ret cert' off len)
            botan_x509_cert_destroy

-- | Load a certificate from a file.
loadCertFile :: HasCallStack => CBytes -> IO Cert
loadCertFile name = do
    CB.withCBytesUnsafe name $ \ name' ->
        Cert <$> newBotanStruct
            (`botan_x509_cert_load_file` name')
            botan_x509_cert_destroy

-- | Create a new object that refers to the same certificate.
dupCert :: HasCallStack => Cert -> IO Cert
dupCert cert = do
    withCert cert $ \ cert' ->
        Cert <$> newBotanStruct
            (`botan_x509_cert_dup` cert')
            botan_x509_cert_destroy

{- NO IMPLEMENTED IN BOTAN
-- | Create a new self-signed X.509 certificate.
-- Generating a new self-signed certificate can often be useful, for example when setting up a new root CA, or for use in specialized protocols.
newCertSelfsigned ::
  -- | the private key you wish to use (the public key, used in the certificate itself is extracted from the private key)
  PrivKey ->
  RNG ->
  -- | common name
  CBytes ->
  -- | org name
  CBytes ->
  IO Cert
newCertSelfsigned (PrivKey key) rng common org =
    withBotanStruct key $ \ key' ->
    withRNG rng $ \ rng' ->
    CB.withCBytesUnsafe common $ \ common' ->
    CB.withCBytesUnsafe org $ \ org' ->
        Cert <$> newBotanStruct
            (\ ret -> botan_x509_cert_gen_selfsigned ret key' rng' common' org')
            botan_x509_cert_destroy
-}

-- | Return the time the certificate becomes valid, as a 'T.Text' in form “YYYYMMDDHHMMSSZ” where Z is a literal character reflecting that this time is relative to UTC.
certStartText :: Cert -> IO T.Text
certStartText cert =
    withCert cert $ \ cert' ->
    allocBotanBufferUTF8Unsafe 16 (botan_x509_cert_get_time_starts cert')

-- | Return the time the certificate expires, as a 'T.Text' in form “YYYYMMDDHHMMSSZ” where Z is a literal character reflecting that this time is relative to UTC.
certExpireText :: Cert -> IO T.Text
certExpireText cert =
    withCert cert $ \ cert' ->
    allocBotanBufferUTF8Unsafe 16 (botan_x509_cert_get_time_expires cert')

-- | Return the time the certificate becomes valid, as seconds since epoch.
certStart :: Cert -> IO Word64
certStart cert =
    withCert cert $ \ cert' -> do
        (a, _) <- allocPrimUnsafe @Word64 $ botan_x509_cert_not_before cert'
        return a

-- | Return the time the certificate becomes valid.
certStart' :: Cert -> IO SystemTime
certStart' cert = do
    !r <- fromIntegral <$> certStart cert
    return (MkSystemTime r 0)

-- | Return the time the certificate expires, as 'SystemTime'.
certExpire :: Cert -> IO Word64
certExpire cert =
    withCert cert $ \ cert' -> do
        (a, _) <- allocPrimUnsafe @Word64 $ botan_x509_cert_not_after cert'
        return a

-- | Return the time the certificate expires, as 'SystemTime'.
certExpire' :: Cert -> IO SystemTime
certExpire' cert = do
    !r <- fromIntegral <$> certExpire cert
    return (MkSystemTime r 0)

-- | Return the finger print of the certificate.
certFingerPrint :: Cert -> HashType -> IO T.Text
certFingerPrint cert ht =
    withCert cert $ \ cert' ->
    CB.withCBytesUnsafe (hashTypeToCBytes ht) $ \ ht' ->
    allocBotanBufferUTF8Unsafe V.smallChunkSize $
        botan_x509_cert_get_fingerprint cert' ht'

-- | Return the serial number of the certificate.
certSerial :: Cert -> IO V.Bytes
certSerial cert =
    withCert cert $ \ cert' ->
    allocBotanBufferUnsafe 64 $
        botan_x509_cert_get_serial_number cert'

-- | Return the authority key ID set in the certificate, which may be empty.
certIDAuthority :: Cert -> IO V.Bytes
certIDAuthority cert =
    withCert cert $ \ cert' ->
    allocBotanBufferUnsafe 64 $
        botan_x509_cert_get_authority_key_id cert'

-- | Return the subject key ID set in the certificate, which may be empty.
certIDSubject :: Cert -> IO V.Bytes
certIDSubject cert =
    withCert cert $ \ cert' ->
    allocBotanBufferUnsafe 64 $
        botan_x509_cert_get_subject_key_id cert'

-- | Get the serialized representation of the public key included in this certificate.
certPubBits :: Cert -> IO V.Bytes
certPubBits cert =
    withCert cert $ \ cert' ->
    allocBotanBufferUnsafe V.smallChunkSize $
        botan_x509_cert_get_public_key_bits cert'

-- | Get the public key included in this certificate.
certPubKey :: Cert -> IO PubKey
certPubKey cert = do
    withCert cert $ \ cert' ->
        PubKey <$> newBotanStruct
            (cert' `botan_x509_cert_get_public_key`)
            botan_pubkey_destroy

-- | Get a value from the issuer DN field.
certDNIssuer ::
    Cert ->
    -- | key
    CBytes ->
    -- | index
    Int ->
    IO T.Text
certDNIssuer cert key ix =
    withCert cert $ \ cert' ->
    CB.withCBytesUnsafe key $ \ key' -> do
    allocBotanBufferUTF8Unsafe 64 $
        botan_x509_cert_get_issuer_dn cert' key' ix

-- | Get a value from the subject DN field.
certDNSubject ::
  Cert ->
  -- | key
  CBytes ->
  -- | index
  Int ->
  IO T.Text
certDNSubject cert key ix =
    withCert cert $ \ cert' ->
    CB.withCBytesUnsafe key $ \ key' ->
    allocBotanBufferUTF8Unsafe 64 $
        botan_x509_cert_get_subject_dn cert' key' ix

-- | Format the certificate as a free-form string.
certToText :: Cert -> IO T.Text
certToText cert =
    withCert cert $ \ cert' ->
    T.Text . V.unsafeInit <$>
        allocBotanBufferUnsafe V.smallChunkSize (botan_x509_cert_to_string cert')

-- | Change cert's 'KeyUsageConstraint'.
certUsage :: Cert -> KeyUsageConstraint -> IO ()
certUsage cert usage =
    withCert cert $ \ cert' ->
    throwBotanIfMinus_ $ botan_x509_cert_allowed_usage cert' usage

-- Verify a certificate. Returns 'Nothing' if validation was successful, 'Just reason' if unsuccessful.
--
verifyCert ::
    -- | Intermediate certificates, set to @[]@ if not needed.
    [Cert] ->
    -- | Trusted certificates, set to @[]@ if not needed.
    [Cert] ->
    -- | Set required strength to indicate the minimum key and hash strength that is allowed, set to zero to use default(110).
    Int ->
    -- | Hostname.
    CBytes ->
    -- | Set reference time(seconds since epoch) to be the time which the certificate chain is validated against. Use zero to use the current system clock.
    Word64 ->
    -- | The certificate to be verified.
    Cert ->
    IO (Maybe CBytes)
verifyCert intermediates trusted strength hostname refTime cert =
    withCert cert $ \ cert' ->
    withCPtrsUnsafe (map certStruct intermediates) $ \ intermediates' intermediatesLen ->
    withCPtrsUnsafe (map certStruct trusted) $ \ trusted' trustedLen ->
    CB.withCBytesUnsafe hostname $ \ hostname' -> do
        a <- throwBotanIfMinus $
            hs_botan_x509_cert_verify cert'
                intermediates' intermediatesLen
                trusted' trustedLen
                strength hostname' refTime
        if a == 0
        then return Nothing
        else let !reason = certValidateStatus a in return (Just reason)

-- | Return a (statically allocated) CString associated with the verification result.
certValidateStatus :: CInt -> CBytes
certValidateStatus r =
    unsafeDupablePerformIO $ CB.fromCString =<< botan_x509_cert_validation_status r

-- | Certificate path validation supporting Certificate Revocation Lists.
--
-- Verify a certificate. Returns 'Nothing' if validation was successful, 'Just reason' if unsuccessful.
--
verifyCertCRL ::
    -- | Intermediate certificates, set to @[]@ if not needed.
    [Cert] ->
    -- | Trusted certificates, set to @[]@ if not needed.
    [Cert] ->
    -- | Certificate Revocation Lists, set to @[]@ if not needed.
    [CRL] ->
    -- | Set required strength to indicate the minimum key and hash strength that is allowed, set to zero to use default(110).
    Int ->
    -- | Hostname.
    CBytes ->
    -- | Set reference time(seconds since epoch) to be the time which the certificate chain is validated against. Use zero to use the current system clock.
    Word64 ->
    -- | The certificate to be verified.
    Cert ->
    IO (Maybe CBytes)
verifyCertCRL intermediates trusted crls strength hostname refTime cert =
    withCert cert $ \ cert' ->
    withCPtrsUnsafe (map certStruct intermediates) $ \ intermediates' intermediatesLen ->
    withCPtrsUnsafe (map certStruct trusted) $ \ trusted' trustedLen ->
    withCPtrsUnsafe (map crlStruct crls) $ \ crls' crlsLen ->
    CB.withCBytesUnsafe hostname $ \ hostname' -> do
        a <- throwBotanIfMinus $
            hs_botan_x509_cert_verify_with_crl cert'
                intermediates' intermediatesLen
                trusted' trustedLen
                crls' crlsLen
                strength hostname' refTime
        if a == 0
        then return Nothing
        else let !reason = certValidateStatus a in return (Just reason)

-- | Certificate path validation supporting Certificate Revocation Lists with a 'CertStore'.
--
-- Verify a certificate. Returns 'Nothing' if validation was successful, 'Just reason' if unsuccessful.
--
verifyCertCRL' ::
    -- | Intermediate certificates, set to @[]@ if not needed.
    [Cert] ->
    -- | Trusted certificates in 'CertStore'
    CertStore ->
    -- | Certificate Revocation Lists, set to @[]@ if not needed.
    [CRL] ->
    -- | Set required strength to indicate the minimum key and hash strength that is allowed, set to zero to use default(110).
    Int ->
    -- | Hostname.
    CBytes ->
    -- | Set reference time(seconds since epoch) to be the time which the certificate chain is validated against. Use zero to use the current system clock.
    Word64 ->
    -- | The certificate to be verified.
    Cert ->
    IO (Maybe CBytes)
verifyCertCRL' intermediates store crls strength hostname refTime cert =
    withCert cert $ \ cert' ->
    withCertStore store $ \ store' ->
    withCPtrsUnsafe (map certStruct intermediates) $ \ intermediates' intermediatesLen ->
    withCPtrsUnsafe (map crlStruct crls) $ \ crls' crlsLen ->
    CB.withCBytesUnsafe hostname $ \ hostname' -> do
        a <- throwBotanIfMinus $
            hs_botan_x509_cert_verify_with_certstore_crl cert'
                intermediates' intermediatesLen
                store'
                crls' crlsLen
                strength hostname' refTime
        if a == 0
        then return Nothing
        else let !reason = certValidateStatus a in return (Just reason)

----------------------------------------
-- X.509 Certificate Revocation Lists --
----------------------------------------

-- | An opaque newtype wrapper for an X.509 Certificate Revocation Lists.
--
-- It will occasionally happen that a certificate must be revoked before its expiration date.
-- Examples of this happening include the private key being compromised, or the user to which it has been assigned leaving an organization.
-- Certificate revocation lists are an answer to this problem (though online certificate validation techniques are starting to become somewhat more popular).
-- Every once in a while the CA will release a new CRL, listing all certificates that have been revoked.
-- Also included is various pieces of information like what time a particular certificate was revoked, and for what reason.
-- In most systems, it is wise to support some form of certificate revocation, and CRLs handle this easily.
newtype CRL = CRL { crlStruct :: BotanStruct }
    deriving (Show, Generic)
    deriving anyclass T.Print

withCRL :: HasCallStack => CRL -> (BotanStructT -> IO r) -> IO r
withCRL (CRL crl) = withBotanStruct crl

-- | Load a CRL from the DER or PEM representation.
loadCRL :: V.Bytes -> IO CRL
loadCRL src =
    withPrimVectorUnsafe src $ \ src' off len ->
    CRL <$> newBotanStruct
        (\ ret -> hs_botan_x509_crl_load ret src' off len)
        botan_x509_crl_destroy

-- | Load a CRL from a file.
loadCRLFile :: CBytes -> IO CRL
loadCRLFile src =
    CB.withCBytesUnsafe src $ \ src' ->
    CRL <$> newBotanStruct
        (`botan_x509_crl_load_file` src')
        botan_x509_crl_destroy

-- | Check whether a given crl contains a given cert. Return True when the certificate is revoked, False otherwise.
isRevokedX509 :: HasCallStack => CRL -> Cert -> IO Bool
isRevokedX509 crl cert =
    withCRL crl $ \ crl' ->
    withCert cert $ \ cert' -> do
        ret <- botan_x509_is_revoked crl' cert'
        if ret == 0
        then return True
        else if ret == -1
            then return False
            else throwBotanError ret

----------------------------------------
-- X.509 Certificate Store            --
----------------------------------------

-- | An opaque newtype wrapper for an X.509 Certificate Store based on botan's 'FlatFile_Certificate_Store'.
newtype CertStore = CertStore { certStoreStruct :: BotanStruct }
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Use 'CertStore' as a 'botan_x509_certstore_t'.
withCertStore :: HasCallStack => CertStore -> (BotanStructT -> IO r) -> IO r
withCertStore (CertStore c) = withBotanStruct c

-- | Load a CertStore from a file.
loadCertStoreFile :: CBytes -> IO CertStore
loadCertStoreFile src =
    CB.withCBytesUnsafe src $ \ src' ->
    CertStore <$> newBotanStruct
        (`botan_x509_certstore_load_file` src')
        botan_x509_certstore_destroy
