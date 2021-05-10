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
module Z.Crypto.X509 (
  -- * X509 Certificates
    X509Cert, withX509Cert
  , loadX509Cert, loadX509CertFile, dupX509Cert
  -- * read X509 field
  , x509CertStart, x509CertExpire
  , x509CertStart', x509CertExpire'
  , x509CertStartText, x509CertExpireText
  , x509CertFingerPrint
  , x509CertSerial
  , x509CertIDAuthority
  , x509CertIDSubject
  , x509CertPubBits
  , x509CertPubKey
  , x509CertDNIssuer
  , x509CertDNSubject
  , x509CertToText
  , x509CertUsage
  -- * verify certificate
  , verifyX509Cert
  , verifyX509CertCRL
  -- * CRL
  , X509CRL
  , withX509CRL, loadX509CRL, loadX509CRLFile, isRevokedX509
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
newtype X509Cert = X509Cert { certStruct :: BotanStruct }
    deriving (Show, Generic)
    deriving anyclass T.Print

withX509Cert :: HasCallStack => X509Cert -> (BotanStructT -> IO r) -> IO r
withX509Cert (X509Cert cert) = withBotanStruct cert

-- | Load a certificate from the DER or PEM representation.
loadX509Cert :: HasCallStack => V.Bytes -> IO X509Cert
loadX509Cert cert = do
    withPrimVectorUnsafe cert $ \ cert' off len ->
        X509Cert <$> newBotanStruct
            (\ ret -> hs_botan_x509_cert_load ret cert' off len)
            botan_x509_cert_destroy

-- | Load a certificate from a file.
loadX509CertFile :: HasCallStack => CBytes -> IO X509Cert
loadX509CertFile name = do
    CB.withCBytesUnsafe name $ \ name' ->
        X509Cert <$> newBotanStruct
            (`botan_x509_cert_load_file` name')
            botan_x509_cert_destroy

-- | Create a new object that refers to the same certificate.
dupX509Cert :: HasCallStack => X509Cert -> IO X509Cert
dupX509Cert cert = do
    withX509Cert cert $ \ cert' ->
        X509Cert <$> newBotanStruct
            (`botan_x509_cert_dup` cert')
            botan_x509_cert_destroy

{- NO IMPLEMENTED IN BOTAN
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
newX509CertSelfsigned (PrivKey key) rng common org =
    withBotanStruct key $ \ key' ->
    withRNG rng $ \ rng' ->
    CB.withCBytesUnsafe common $ \ common' ->
    CB.withCBytesUnsafe org $ \ org' ->
        X509Cert <$> newBotanStruct
            (\ ret -> botan_x509_cert_gen_selfsigned ret key' rng' common' org')
            botan_x509_cert_destroy
-}

-- | Return the time the certificate becomes valid, as a 'T.Text' in form “YYYYMMDDHHMMSSZ” where Z is a literal character reflecting that this time is relative to UTC.
x509CertStartText :: X509Cert -> IO T.Text
x509CertStartText cert =
    withX509Cert cert $ \ cert' ->
    allocBotanBufferUTF8Unsafe 16 (botan_x509_cert_get_time_starts cert')

-- | Return the time the certificate expires, as a 'T.Text' in form “YYYYMMDDHHMMSSZ” where Z is a literal character reflecting that this time is relative to UTC.
x509CertExpireText :: X509Cert -> IO T.Text
x509CertExpireText cert =
    withX509Cert cert $ \ cert' ->
    allocBotanBufferUTF8Unsafe 16 (botan_x509_cert_get_time_expires cert')

-- | Return the time the certificate becomes valid, as seconds since epoch.
x509CertStart :: X509Cert -> IO Word64
x509CertStart cert =
    withX509Cert cert $ \ cert' -> do
        (a, _) <- allocPrimUnsafe @Word64 $ botan_x509_cert_not_before cert'
        return a

-- | Return the time the certificate becomes valid.
x509CertStart' :: X509Cert -> IO SystemTime
x509CertStart' cert = do
    !r <- fromIntegral <$> x509CertStart cert
    return (MkSystemTime r 0)

-- | Return the time the certificate expires, as 'SystemTime'.
x509CertExpire :: X509Cert -> IO Word64
x509CertExpire cert =
    withX509Cert cert $ \ cert' -> do
        (a, _) <- allocPrimUnsafe @Word64 $ botan_x509_cert_not_after cert'
        return a

-- | Return the time the certificate expires, as 'SystemTime'.
x509CertExpire' :: X509Cert -> IO SystemTime
x509CertExpire' cert = do
    !r <- fromIntegral <$> x509CertExpire cert
    return (MkSystemTime r 0)

-- | Return the finger print of the certificate.
x509CertFingerPrint :: X509Cert -> HashType -> IO T.Text
x509CertFingerPrint cert ht =
    withX509Cert cert $ \ cert' ->
    CB.withCBytesUnsafe (hashTypeToCBytes ht) $ \ ht' ->
    allocBotanBufferUTF8Unsafe V.smallChunkSize $
        botan_x509_cert_get_fingerprint cert' ht'

-- | Return the serial number of the certificate.
x509CertSerial :: X509Cert -> IO V.Bytes
x509CertSerial cert =
    withX509Cert cert $ \ cert' ->
    allocBotanBufferUnsafe 64 $
        botan_x509_cert_get_serial_number cert'

-- | Return the authority key ID set in the certificate, which may be empty.
x509CertIDAuthority :: X509Cert -> IO V.Bytes
x509CertIDAuthority cert =
    withX509Cert cert $ \ cert' ->
    allocBotanBufferUnsafe 64 $
        botan_x509_cert_get_authority_key_id cert'

-- | Return the subject key ID set in the certificate, which may be empty.
x509CertIDSubject :: X509Cert -> IO V.Bytes
x509CertIDSubject cert =
    withX509Cert cert $ \ cert' ->
    allocBotanBufferUnsafe 64 $
        botan_x509_cert_get_subject_key_id cert'

-- | Get the serialized representation of the public key included in this certificate.
x509CertPubBits :: X509Cert -> IO V.Bytes
x509CertPubBits cert =
    withX509Cert cert $ \ cert' ->
    allocBotanBufferUnsafe V.smallChunkSize $
        botan_x509_cert_get_public_key_bits cert'

-- | Get the public key included in this certificate.
x509CertPubKey :: X509Cert -> IO PubKey
x509CertPubKey cert = do
    withX509Cert cert $ \ cert' ->
        PubKey <$> newBotanStruct
            (cert' `botan_x509_cert_get_public_key`)
            botan_pubkey_destroy

-- | Get a value from the issuer DN field.
x509CertDNIssuer ::
    X509Cert ->
    -- | key
    CBytes ->
    -- | index
    Int ->
    IO T.Text
x509CertDNIssuer cert key ix =
    withX509Cert cert $ \ cert' ->
    CB.withCBytesUnsafe key $ \ key' -> do
    allocBotanBufferUTF8Unsafe 64 $
        botan_x509_cert_get_issuer_dn cert' key' ix

-- | Get a value from the subject DN field.
x509CertDNSubject ::
  X509Cert ->
  -- | key
  CBytes ->
  -- | index
  Int ->
  IO T.Text
x509CertDNSubject cert key ix =
    withX509Cert cert $ \ cert' ->
    CB.withCBytesUnsafe key $ \ key' ->
    allocBotanBufferUTF8Unsafe 64 $
        botan_x509_cert_get_subject_dn cert' key' ix

-- | Format the certificate as a free-form string.
x509CertToText :: X509Cert -> IO T.Text
x509CertToText cert =
    withX509Cert cert $ \ cert' ->
    T.Text . V.unsafeInit <$>
        allocBotanBufferUnsafe V.smallChunkSize (botan_x509_cert_to_string cert')

-- | Change cert's 'KeyUsageConstraint'.
x509CertUsage :: X509Cert -> KeyUsageConstraint -> IO ()
x509CertUsage cert usage =
    withX509Cert cert $ \ cert' ->
    throwBotanIfMinus_ $ botan_x509_cert_allowed_usage cert' usage

-- Verify a certificate. Returns 'Nothing' if validation was successful, 'Just reason' if unsuccessful.
--
verifyX509Cert ::
    -- | Intermediate certificates, set to @[]@ if not needed.
    [X509Cert] ->
    -- | Trusted certificates, set to @[]@ if not needed.
    [X509Cert] ->
    -- | The trusted path which refers to a directory where one or more trusted CA certificates are stored. It may be empty if not needed.
    CBytes ->
    -- | Set required strength to indicate the minimum key and hash strength that is allowed.
    Int ->
    -- | Hostname.
    CBytes ->
    -- | Set reference time(seconds since epoch) to be the time which the certificate chain is validated against. Use zero to use the current system clock.
    Word64 ->
    -- | The certificate to be verified.
    X509Cert ->
    IO (Maybe CBytes)
verifyX509Cert intermediates trusted path strength hostname refTime cert =
    withX509Cert cert $ \ cert' ->
    withCPtrs (map certStruct intermediates) $ \ intermediates' intermediatesLen ->
    withCPtrs (map certStruct trusted) $ \ trusted' trustedLen ->
    CB.withCBytes path $ \ path' ->
    CB.withCBytes hostname $ \ hostname' -> do
        a <- throwBotanIfMinus $
            hs_botan_x509_cert_verify cert'
                intermediates' intermediatesLen
                trusted' trustedLen
                path' strength hostname' refTime
        if a == 0
        then return Nothing
        else let !reason = x509CertValidateStatus a in return (Just reason)

-- | Return a (statically allocated) CString associated with the verification result.
x509CertValidateStatus :: CInt -> CBytes
x509CertValidateStatus r =
    unsafeDupablePerformIO $ CB.fromCString =<< botan_x509_cert_validation_status r

-- | Certificate path validation supporting Certificate Revocation Lists.
--
-- Verify a certificate. Returns 'Nothing' if validation was successful, 'Just reason' if unsuccessful.
--
verifyX509CertCRL ::
    -- | Intermediate certificates, set to NULL if not needed.
    [X509Cert] ->
    -- | Trusted certificates, set to NULL if not needed.
    [X509Cert] ->
    -- | Certificate Revocation Lists, set to NULL if not needed.
    [X509CRL] ->
    -- | The trusted path which refers to a directory where one or more trusted CA certificates are stored. It may be NULL if not needed.
    CBytes ->
    -- | Set required strength to indicate the minimum key and hash strength that is allowed.
    Int ->
    -- | Hostname.
    CBytes ->
    -- | Set reference time(seconds since epoch) to be the time which the certificate chain is validated against. Use zero to use the current system clock.
    Word64 ->
    -- | The certificate to be verified.
    X509Cert ->
    IO (Maybe CBytes)
verifyX509CertCRL intermediates trusted crls path strength hostname refTime cert =
    withX509Cert cert $ \ cert' ->
    withCPtrs (map certStruct intermediates) $ \ intermediates' intermediatesLen ->
    withCPtrs (map certStruct trusted) $ \ trusted' trustedLen ->
    withCPtrs (map crlStruct crls) $ \ crls' crlsLen ->
    CB.withCBytes path $ \ path' ->
    CB.withCBytes hostname $ \ hostname' -> do
        a <- throwBotanIfMinus $
            hs_botan_x509_cert_verify_with_crl cert'
                intermediates' intermediatesLen
                trusted' trustedLen
                crls' crlsLen
                path' strength hostname' refTime
        if a == 0
        then return Nothing
        else let !reason = x509CertValidateStatus a in return (Just reason)

----------------------------------------
-- X.509 Certificate Revocation Lists --
----------------------------------------

-- | An opaque newtype wrapper for an X.509 Certificate Revocation Lists.
newtype X509CRL = X509CRL { crlStruct :: BotanStruct }
    deriving (Show, Generic)
    deriving anyclass T.Print

withX509CRL :: HasCallStack => X509CRL -> (BotanStructT -> IO r) -> IO r
withX509CRL (X509CRL crl) = withBotanStruct crl

-- | Load a CRL from the DER or PEM representation.
loadX509CRL :: V.Bytes -> IO X509CRL
loadX509CRL src =
    withPrimVectorUnsafe src $ \ src' off len ->
    X509CRL <$> newBotanStruct
        (\ ret -> hs_botan_x509_crl_load ret src' off len)
        botan_x509_crl_destroy

-- | Load a CRL from a file.
loadX509CRLFile :: CBytes -> IO X509CRL
loadX509CRLFile src =
    CB.withCBytesUnsafe src $ \ src' ->
    X509CRL <$> newBotanStruct
        (`botan_x509_crl_load_file` src')
        botan_x509_cert_destroy

-- | Check whether a given crl contains a given cert. Return True when the certificate is revoked, False otherwise.
isRevokedX509 :: HasCallStack => X509CRL -> X509Cert -> IO Bool
isRevokedX509 crl cert =
    withX509CRL crl $ \ crl' ->
    withX509Cert cert $ \ cert' -> do
        ret <- botan_x509_is_revoked crl' cert'
        if ret == 0
        then return True
        else if ret == -1
            then return False
            else throwBotanError ret
