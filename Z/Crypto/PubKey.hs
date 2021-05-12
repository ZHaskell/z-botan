{-|
Module      : Z.Crypto.PubKey
Description : Public Key Cryptography
Copyright   : Dong Han, 2021
              AnJie Dong, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

This module is used for Public key cryptography. Public key cryptography (also called asymmetric cryptography) is a collection of techniques allowing for encryption, signatures, and key agreement.
-}

module Z.Crypto.PubKey (
  -- * Asymmetric cryptography algorithms
    KeyType(..)
  -- * Key generation and manipulation
  , PrivKey(..), PubKey(..)
  , newPrivKey, newKeyPair, privKeyToPubKey
  , loadPrivKey
  , privKeyAlgoName
  , privKeyParam
  , exportPrivKeyDER, exportPrivKeyPEM
  , exportPrivKeyEncryptedDER, exportPrivKeyEncryptedPEM
  , loadPubKey
  , pubKeyAlgoName
  , pubKeyParam
  , exportPubKeyDER
  , exportPubKeyPEM
  , estStrength
  , fingerPrintPubKey
  -- * Encrypt & Decrypt
  , pkEncrypt
  , pkDecrypt
  , sm2Encrypt
  , sm2Decrypt
  , EMEPadding(..)
  -- * Sign & verify
  , EMSA(..), SignFmt(..)
  , newSigner, updateSigner, finalSigner, sinkToSigner, sign, signChunks
  , newVerifier, updateVerifier, finalVerifier, sinkToVerifier, verify, verifyChunks
  -- * Key agreement
  , KeyAgreement(..)
  , newKeyAgreement
  , exportKeyAgreementPublic
  , keyAgree
  -- * RSA specific
  , getRSAParams
  , newRSAPrivKey
  , getRSAPubParams
  , newRSAPubKey
  -- * DSA specific
  , getDSAPrivParams
  , newDSAPrivKey
  , getDSAPubParams
  , newDSAPubKey
  -- * ElGamal specific
  , getElGamalPrivParams
  , newElGamalPrivKey
  , getElGamalPubParams
  , newElGamalPubKey
  -- * Diffie-Hellman specific
  , getDHPrivParams
  , newDHPrivKey
  , getDHPubParams
  , newDHPubKey
  -- * constants
  , XMSSType
  , pattern XMSS_SHA2_10_256
  , pattern XMSS_SHA2_16_256
  , pattern XMSS_SHA2_20_256
  , pattern XMSS_SHA2_10_512
  , pattern XMSS_SHA2_16_512
  , pattern XMSS_SHA2_20_512
  , pattern XMSS_SHAKE_10_256
  , pattern XMSS_SHAKE_16_256
  , pattern XMSS_SHAKE_20_256
  , pattern XMSS_SHAKE_10_512
  , pattern XMSS_SHAKE_16_512
  , pattern XMSS_SHAKE_20_512
  , ECGroup
  , pattern Secp160k1
  , pattern Secp160r1
  , pattern Secp160r2
  , pattern Secp192k1
  , pattern Secp192r1
  , pattern Secp224k1
  , pattern Secp224r1
  , pattern Secp256k1
  , pattern Secp256r1
  , pattern Secp384r1
  , pattern Secp521r1
  , pattern Brainpool160r1
  , pattern Brainpool192r1
  , pattern Brainpool224r1
  , pattern Brainpool256r1
  , pattern Brainpool320r1
  , pattern Brainpool384r1
  , pattern Brainpool512r1
  , pattern X962_p192v2
  , pattern X962_p192v3
  , pattern X962_p239v1
  , pattern X962_p239v2
  , pattern X962_p239v3
  , pattern Gost_256A
  , pattern Gost_512A
  , pattern Frp256v1
  , pattern Sm2p256v1
  , DLGroup
  , pattern FFDHE_IETF_2048
  , pattern FFDHE_IETF_3072
  , pattern FFDHE_IETF_4096
  , pattern FFDHE_IETF_6144
  , pattern FFDHE_IETF_8192
  , pattern MODP_IETF_1024
  , pattern MODP_IETF_1536
  , pattern MODP_IETF_2048
  , pattern MODP_IETF_3072
  , pattern MODP_IETF_4096
  , pattern MODP_IETF_6144
  , pattern MODP_IETF_8192
  , pattern MODP_SRP_1024
  , pattern MODP_SRP_1536
  , pattern MODP_SRP_2048
  , pattern MODP_SRP_3072
  , pattern MODP_SRP_4096
  , pattern MODP_SRP_6144
  , pattern MODP_SRP_8192
  , pattern DSA_JCE_1024
  , pattern DSA_BOTAN_2048
  , pattern DSA_BOTAN_3072
  -- * re-exports
  , HashType(..)
  , KDFType(..)
  -- * internal
  , withPrivKey
  , withPubKey
  ) where

import           Data.Word
import           GHC.Generics
import           System.IO.Unsafe    (unsafePerformIO)
import           Z.Botan.Exception
import           Z.Botan.FFI
import           Z.Crypto.Hash       (HashType(..), hashTypeToCBytes)
import           Z.Crypto.KDF        (KDFType(..), kdfTypeToCBytes)
import           Z.Crypto.MPI
import           Z.Crypto.RNG        (RNG, getRNG, withRNG)
import qualified Z.Data.Builder      as B
import           Z.Data.CBytes       (CBytes)

import qualified Z.Data.CBytes       as CB
import qualified Z.Data.Text         as T
import qualified Z.Data.Vector       as V
import           Z.Foreign
import           Z.IO.BIO

---------------
-- Key Types --
---------------

-- | Public key cryptography algorithms.
data KeyType
    = RSA Word32        -- ^ RSA key of the given size, namely n bits, support encryption and signature.
    | SM2 ECGroup       -- ^ Public key algorithms specified by China, support encryption and signature.
    | ElGamal DLGroup   -- ^ ElGamal encryption system, support encryption.

    | DSA DLGroup     -- ^ Digital Signature Algorithm based on the discrete logarithm problem.
    | ECDSA ECGroup   -- ^ Digital Signature Algorithm which uses elliptic curve cryptography.
    | ECKCDSA ECGroup -- ^ Korean Certificate-based Digital Signature Algorithm.
    | ECGDSA ECGroup  -- ^ Elliptic Curve German Digital Signature Algorithm.
    | GOST_34'10 ECGroup -- ^ Cryptographic algorithms defined by the Russian national standards, support signature.
    | Ed25519         -- ^ Ed25519 elliptic-curve signatures, see <https://ed25519.cr.yp.to/ ed25519>.
    | XMSS XMSSType   -- ^ eXtended Merkle Signature Scheme, see <xmss https://botan.randombit.net/handbook/api_ref/pubkey.html#extended-merkle-signature-scheme-xmss>.

    | DH DLGroup        -- ^ The Diffie–Hellman key exchange.
    | ECDH ECGroup      -- ^ The Elliptic-curve Diffie–Hellman key exchange.
    | Curve25519        -- ^ The Curve25519 Diffie–Hellman key exchange.

keyTypeToCBytes :: KeyType -> (CBytes, CBytes)
keyTypeToCBytes keyType = case keyType of
    RSA bits    -> ("RSA", CB.buildCBytes $ B.int bits)
    SM2 grp     -> ("SM2", grp)
    ElGamal grp -> ("ElGamal", grp)
    DSA grp         -> ("DSA", grp)
    ECDSA grp       -> ("ECDSA", grp)
    ECKCDSA grp     -> ("ECKCDSA", grp)
    ECGDSA grp      -> ("ECGDSA", grp)
    GOST_34'10 grp  -> ("GOST_34.10", grp)
    Ed25519         -> ("Ed25519", "")
    XMSS xms        -> ("XMSS", xms)
    DH grp      -> ("DH", grp)
    ECDH grp    -> ("ECDH", grp)
    Curve25519  -> ("Curve25519", "")

-- | A type wrapper.
type XMSSType = CBytes

pattern XMSS_SHA2_10_256 :: XMSSType
pattern XMSS_SHA2_10_256 = "XMSS-SHA2_10_256"

pattern XMSS_SHA2_16_256 :: XMSSType
pattern XMSS_SHA2_16_256 = "XMSS-SHA2_16_256"

pattern XMSS_SHA2_20_256 :: XMSSType
pattern XMSS_SHA2_20_256 = "XMSS-SHA2_20_256"

pattern XMSS_SHA2_10_512 :: XMSSType
pattern XMSS_SHA2_10_512 = "XMSS-SHA2_10_512"

pattern XMSS_SHA2_16_512 :: XMSSType
pattern XMSS_SHA2_16_512 = "XMSS-SHA2_16_512"

pattern XMSS_SHA2_20_512 :: XMSSType
pattern XMSS_SHA2_20_512 = "XMSS-SHA2_20_512"

pattern XMSS_SHAKE_10_256 :: XMSSType
pattern XMSS_SHAKE_10_256 = "XMSS-SHAKE_10_256"

pattern XMSS_SHAKE_16_256 :: XMSSType
pattern XMSS_SHAKE_16_256 = "XMSS-SHAKE_16_256"

pattern XMSS_SHAKE_20_256 :: XMSSType
pattern XMSS_SHAKE_20_256 = "XMSS-SHAKE_20_256"

pattern XMSS_SHAKE_10_512 :: XMSSType
pattern XMSS_SHAKE_10_512 = "XMSS-SHAKE_10_512"

pattern XMSS_SHAKE_16_512 :: XMSSType
pattern XMSS_SHAKE_16_512 = "XMSS-SHAKE_16_512"

pattern XMSS_SHAKE_20_512 :: XMSSType
pattern XMSS_SHAKE_20_512 = "XMSS-SHAKE_20_512"

-- | An elliptic curve.
type ECGroup = CBytes

pattern Secp160k1 :: ECGroup
pattern Secp160k1 = "secp160k1"

pattern Secp160r1 :: ECGroup
pattern Secp160r1 = "secp160r1"

pattern Secp160r2 :: ECGroup
pattern Secp160r2 = "secp160r2"

pattern Secp192k1 :: ECGroup
pattern Secp192k1 = "secp192k1"

pattern Secp192r1 :: ECGroup
pattern Secp192r1 = "secp192r1"

pattern Secp224k1 :: ECGroup
pattern Secp224k1 = "secp224k1"

pattern Secp224r1 :: ECGroup
pattern Secp224r1 = "secp224r1"

pattern Secp256k1 :: ECGroup
pattern Secp256k1 = "secp256k1"

pattern Secp256r1 :: ECGroup
pattern Secp256r1 = "secp256r1"

pattern Secp384r1 :: ECGroup
pattern Secp384r1 = "secp384r1"

pattern Secp521r1 :: ECGroup
pattern Secp521r1 = "secp521r1"

pattern Brainpool160r1 :: ECGroup
pattern Brainpool160r1 = "brainpool160r1"

pattern Brainpool192r1 :: ECGroup
pattern Brainpool192r1 = "brainpool192r1"

pattern Brainpool224r1 :: ECGroup
pattern Brainpool224r1 = "brainpool224r1"

pattern Brainpool256r1 :: ECGroup
pattern Brainpool256r1 = "brainpool256r1"

pattern Brainpool320r1 :: ECGroup
pattern Brainpool320r1 = "brainpool320r1"

pattern Brainpool384r1 :: ECGroup
pattern Brainpool384r1 = "brainpool384r1"

pattern Brainpool512r1 :: ECGroup
pattern Brainpool512r1 = "brainpool512r1"

pattern X962_p192v2 :: ECGroup
pattern X962_p192v2 = "x962_p192v2"

pattern X962_p192v3 :: ECGroup
pattern X962_p192v3 = "x962_p192v3"

pattern X962_p239v1 :: ECGroup
pattern X962_p239v1 = "x962_p239v1"

pattern X962_p239v2 :: ECGroup
pattern X962_p239v2 = "x962_p239v2"

pattern X962_p239v3 :: ECGroup
pattern X962_p239v3 = "x962_p239v3"

pattern Gost_256A :: ECGroup
pattern Gost_256A = "gost_256A"

pattern Gost_512A :: ECGroup
pattern Gost_512A = "gost_512A"

pattern Frp256v1 :: ECGroup
pattern Frp256v1 = "frp256v1"

pattern Sm2p256v1 :: ECGroup
pattern Sm2p256v1 = "sm2p256v1"

-- | Discrete Logarithm Group
type DLGroup = CBytes

pattern FFDHE_IETF_2048 :: DLGroup
pattern FFDHE_IETF_2048 = "ffdhe/ietf/2048"

pattern FFDHE_IETF_3072 :: DLGroup
pattern FFDHE_IETF_3072 = "ffdhe/ietf/3072"

pattern FFDHE_IETF_4096 :: DLGroup
pattern FFDHE_IETF_4096 = "ffdhe/ietf/4096"

pattern FFDHE_IETF_6144 :: DLGroup
pattern FFDHE_IETF_6144 = "ffdhe/ietf/6144"

pattern FFDHE_IETF_8192 :: DLGroup
pattern FFDHE_IETF_8192 = "ffdhe/ietf/8192"

pattern MODP_IETF_1024 :: DLGroup
pattern MODP_IETF_1024 = "modp/ietf/1024"

pattern MODP_IETF_1536 :: DLGroup
pattern MODP_IETF_1536 = "modp/ietf/1536"

pattern MODP_IETF_2048 :: DLGroup
pattern MODP_IETF_2048 = "modp/ietf/2048"

pattern MODP_IETF_3072 :: DLGroup
pattern MODP_IETF_3072 = "modp/ietf/3072"

pattern MODP_IETF_4096 :: DLGroup
pattern MODP_IETF_4096 = "modp/ietf/4096"

pattern MODP_IETF_6144 :: DLGroup
pattern MODP_IETF_6144 = "modp/ietf/6144"

pattern MODP_IETF_8192 :: DLGroup
pattern MODP_IETF_8192 = "modp/ietf/8192"

pattern MODP_SRP_1024 :: DLGroup
pattern MODP_SRP_1024 = "modp/srp/1024"

pattern MODP_SRP_1536 :: DLGroup
pattern MODP_SRP_1536 = "modp/srp/1536"

pattern MODP_SRP_2048 :: DLGroup
pattern MODP_SRP_2048 = "modp/srp/2048"

pattern MODP_SRP_3072 :: DLGroup
pattern MODP_SRP_3072 = "modp/srp/3072"

pattern MODP_SRP_4096 :: DLGroup
pattern MODP_SRP_4096 = "modp/srp/4096"

pattern MODP_SRP_6144 :: DLGroup
pattern MODP_SRP_6144 = "modp/srp/6144"

pattern MODP_SRP_8192 :: DLGroup
pattern MODP_SRP_8192 = "modp/srp/8192"

pattern DSA_JCE_1024 :: DLGroup
pattern DSA_JCE_1024 = "dsa/jce/1024"

pattern DSA_BOTAN_2048 :: DLGroup
pattern DSA_BOTAN_2048 = "dsa/botan/2048"

pattern DSA_BOTAN_3072 :: DLGroup
pattern DSA_BOTAN_3072 = "dsa/botan/3072"

---------------------------
-- Private Key Functions --
---------------------------

-- | An opaque data type for a private-public key pair.
newtype PrivKey = PrivKey BotanStruct
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Pass 'PrivKey' to FFI.
withPrivKey :: HasCallStack
            => PrivKey -> (BotanStructT -> IO r) -> IO r
{-# INLINABLE withPrivKey  #-}
withPrivKey (PrivKey key) = withBotanStruct key

-- | Creating a new key pair.
--
newKeyPair :: HasCallStack
           => KeyType   -- ^ Algorithm name and some algorithm specific arguments.
           -> RNG
           -> IO (PrivKey, PubKey)
{-# INLINABLE newKeyPair  #-}
newKeyPair kt rng = do
    priv <- newPrivKey kt rng
    let !pub = privKeyToPubKey priv
    return (priv, pub)

-- | Creating a private key.
--
-- Creating a private key requires two things:
--
-- * a source of random numbers
-- * some algorithm specific arguments that define the security level of the resulting key.
--
newPrivKey :: HasCallStack
           => KeyType   -- ^ Algorithm name and some algorithm specific arguments.
           -> RNG
           -> IO PrivKey
{-# INLINABLE newPrivKey  #-}
newPrivKey keyTyp rng =
    withRNG rng $ \ rng' ->
    CB.withCBytes algo $ \ algo' ->
    CB.withCBytes args $ \ args' ->
        PrivKey <$> newBotanStruct'
            (\ key -> botan_privkey_create key algo' args' rng')
            botan_privkey_destroy
    where
        (algo, args) = keyTypeToCBytes keyTyp

-- | Load a private key. If the key is encrypted, password will be used to attempt decryption.
loadPrivKey :: HasCallStack =>
    RNG ->
    V.Bytes ->
    -- | Password.
    CBytes ->
    IO PrivKey
{-# INLINABLE loadPrivKey  #-}
loadPrivKey rng buf passwd =
    withRNG rng $ \ rng' ->
    withPrimVectorUnsafe buf $ \ buf' off len ->
    CB.withCBytesUnsafe passwd $ \ passwd' ->
        PrivKey <$> newBotanStruct
            (\ key -> hs_botan_privkey_load key rng' buf' off len passwd')
            botan_privkey_destroy

-- | Get the algorithm name of a private key.
privKeyAlgoName :: PrivKey -> IO T.Text
{-# INLINABLE privKeyAlgoName  #-}
privKeyAlgoName key =
    withPrivKey key $ allocBotanBufferUTF8Unsafe 16 . botan_privkey_algo_name

-- | Export a private key in DER binary format.
exportPrivKeyDER :: HasCallStack => PrivKey -> V.Bytes
{-# INLINABLE exportPrivKeyDER  #-}
exportPrivKeyDER key = unsafePerformIO $
    withPrivKey key $ \ key' ->
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export key' buf siz 0

-- | Export a private key in PEM textual format.
exportPrivKeyPEM :: HasCallStack => PrivKey -> T.Text
{-# INLINABLE exportPrivKeyPEM  #-}
exportPrivKeyPEM key = unsafePerformIO $
    withPrivKey key $ \ key' ->
    allocBotanBufferUTF8Unsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export key' buf siz 1

-- | Export a private key with password.
exportPrivKeyEncryptedDER :: HasCallStack
                          => PrivKey -> RNG
                          -> CBytes        -- ^ password
                          -> IO V.Bytes
{-# INLINABLE exportPrivKeyEncryptedDER  #-}
exportPrivKeyEncryptedDER key rng pwd =
    withPrivKey key $ \ key' ->
    withRNG rng $ \ rng' ->
    CB.withCBytesUnsafe pwd $ \ pwd' ->
    CB.withCBytesUnsafe "" $ \ pbe' ->   -- currently ignored
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export_encrypted key' buf siz rng' pwd' pbe' 0

-- | Export a private key with password in PEM textual format.
exportPrivKeyEncryptedPEM :: HasCallStack
                          => PrivKey -> RNG
                          -> CBytes        -- ^ password
                          -> IO T.Text
{-# INLINABLE exportPrivKeyEncryptedPEM  #-}
exportPrivKeyEncryptedPEM key rng pwd =
    withPrivKey key $ \ key' ->
    withRNG rng $ \ rng' ->
    CB.withCBytesUnsafe pwd $ \ pwd' ->
    CB.withCBytesUnsafe "" $ \ pbe' ->   -- currently ignored
    allocBotanBufferUTF8Unsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export_encrypted key' buf siz rng' pwd' pbe' 1

-- | Export a public key from a given key pair.
privKeyToPubKey :: PrivKey -> PubKey
{-# INLINABLE privKeyToPubKey  #-}
privKeyToPubKey (PrivKey priv) = unsafePerformIO $ do
    withBotanStruct priv $ \ priv' ->
        PubKey <$> newBotanStruct (`botan_privkey_export_pubkey` priv') botan_privkey_destroy

-- | Read an algorithm specific field from the key pair object.
privKeyParam :: HasCallStack
             => PrivKey      -- ^ key
             -> CBytes       -- ^ field name
             -> MPI
{-# INLINABLE privKeyParam  #-}
privKeyParam key name =
    unsafeNewMPI $ \ mp ->
    withPrivKey key $ \ key' -> do
    throwBotanIfMinus_ (CB.withCBytesUnsafe name (botan_privkey_get_field mp key'))

-- | A newtype wrapper.
newtype PubKey = PubKey BotanStruct
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass T.Print

-- | Pass 'PubKey' to FFI.
withPubKey :: PubKey -> (BotanStructT -> IO r) -> IO r
{-# INLINABLE withPubKey  #-}
withPubKey (PubKey key) = withBotanStruct key

-- | Load a publickey.
loadPubKey :: HasCallStack => V.Bytes -> IO PubKey
{-# INLINABLE loadPubKey  #-}
loadPubKey buf = do
    withPrimVectorUnsafe buf $ \ buf' off len ->
        PubKey <$> newBotanStruct (\ pubKey -> hs_botan_pubkey_load pubKey buf' off len) botan_pubkey_destroy

-- | Export a public key in DER binary format..
exportPubKeyDER :: HasCallStack => PubKey -> V.Bytes
{-# INLINABLE exportPubKeyDER  #-}
exportPubKeyDER pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_pubkey_export pubKey' buf siz 0

-- | Export a public key in PEM textual format.
exportPubKeyPEM :: HasCallStack => PubKey -> T.Text
{-# INLINABLE exportPubKeyPEM  #-}
exportPubKeyPEM pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
    allocBotanBufferUTF8Unsafe V.smallChunkSize $ \ buf siz ->
    botan_pubkey_export pubKey' buf siz 1

-- | Get the algorithm name of a public key.
pubKeyAlgoName :: PubKey -> CBytes
{-# INLINABLE pubKeyAlgoName  #-}
pubKeyAlgoName pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
        CB.fromBytes <$> allocBotanBufferUnsafe 16
            (botan_pubkey_algo_name pubKey')

-- | Estimate the strength of a public key.
estStrength :: PubKey -> Int
{-# INLINABLE estStrength  #-}
estStrength pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' -> do
        (a, _) <- allocPrimUnsafe @CSize $ \ est ->
            throwBotanIfMinus_ (botan_pubkey_estimated_strength pubKey' est)
        return (fromIntegral a)

-- | Fingerprint a given publickey.
fingerPrintPubKey :: PubKey -> HashType -> V.Bytes
{-# INLINABLE fingerPrintPubKey  #-}
fingerPrintPubKey pubKey ht = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
    CB.withCBytesUnsafe (hashTypeToCBytes ht) $ \ hash' ->
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_pubkey_fingerprint pubKey' hash' buf siz

-- | Read an algorithm specific field from the public key object.
pubKeyParam :: PubKey       -- ^ key
            -> CBytes       -- ^ field name
            -> MPI
{-# INLINABLE pubKeyParam  #-}
pubKeyParam pubKey name =
    unsafeNewMPI $ \ mp ->
    withPubKey pubKey $ \ pubKey' -> do
    throwBotanIfMinus_ (CB.withCBytesUnsafe name (botan_pubkey_get_field mp pubKey'))

----------------------------
-- RSA specific functions --
----------------------------


-- | Get RSA parameters
--
-- * Set p to the first RSA prime.
-- * Set q to the second RSA prime.
-- * Set n to the RSA modulus.
-- * Set d to the RSA private exponent.
-- * Set e to the RSA public exponent.
--
getRSAParams :: PrivKey
             -> (MPI, MPI, MPI, MPI, MPI)   -- ^ (p, q, n, d, e)
{-# INLINABLE getRSAParams  #-}
getRSAParams key = (p, q, n, d, e)
  where
    !p = privKeyParam key "p"
    !q = privKeyParam key "q"
    !n = privKeyParam key "n"
    !d = privKeyParam key "d"
    !e = privKeyParam key "e"

-- | Get RSA Public parameters
--
-- * Set n to the RSA modulus.
-- * Set e to the RSA public exponent.
--
getRSAPubParams :: PubKey
                -> (MPI, MPI)   -- ^ (n, e)
{-# INLINABLE getRSAPubParams  #-}
getRSAPubParams key = (n, e)
  where
    !n = pubKeyParam key "n"
    !e = pubKeyParam key "e"

-- | Initialize a RSA key pair using arguments p, q, and e.
newRSAPrivKey :: HasCallStack => MPI -> MPI -> MPI -> PrivKey
{-# INLINABLE newRSAPrivKey  #-}
newRSAPrivKey p q e =
    unsafeWithMPI p $ \ p' ->
    withMPI q $ \ q' ->
    withMPI e $ \ e' ->
        PrivKey <$> newBotanStruct
            (\ key -> botan_privkey_load_rsa key p' q' e')
            botan_privkey_destroy

-- | Initialize a public RSA key using arguments n and e.
newRSAPubKey :: HasCallStack => MPI -> MPI -> PubKey
{-# INLINABLE newRSAPubKey  #-}
newRSAPubKey n e = do
    unsafeWithMPI n $ \ n' ->
        withMPI e $ \ e' ->
            PubKey <$> newBotanStruct (\ pubKey -> botan_pubkey_load_rsa pubKey n' e') botan_pubkey_destroy

----------------------------
-- DSA specific functions --
----------------------------

-- | Get DSA parameters
--
-- * Set p, q, g to group parameters
-- * Set x to the private key
--
getDSAPrivParams :: PrivKey
                 -> (MPI, MPI, MPI, MPI)   -- ^ (p, q, g, x)
{-# INLINABLE getDSAPrivParams  #-}
getDSAPrivParams key = (p, q, g, x)
  where
    !p = privKeyParam key "p"
    !q = privKeyParam key "q"
    !g = privKeyParam key "g"
    !x = privKeyParam key "x"

-- | Initialize a DSA key pair using arguments p, q, g and x.
newDSAPrivKey :: HasCallStack => MPI -> MPI -> MPI -> MPI -> PrivKey
{-# INLINABLE newDSAPrivKey  #-}
newDSAPrivKey p q g x =
    unsafeWithMPI p $ \ p' ->
    withMPI q $ \ q' ->
    withMPI g $ \ g' ->
    withMPI x $ \ x' ->
        PrivKey <$> newBotanStruct
            (\ key -> botan_privkey_load_dsa key p' q' g' x')
            botan_privkey_destroy

-- | Get DSA parameters
--
-- * Set p, q, g to group parameters
-- * Set y to the public key
--
getDSAPubParams :: PubKey
                -> (MPI, MPI, MPI, MPI)   -- ^ (p, q, g, y)
{-# INLINABLE getDSAPubParams  #-}
getDSAPubParams key = (p, q, g, y)
  where
    !p = pubKeyParam key "p"
    !q = pubKeyParam key "q"
    !g = pubKeyParam key "g"
    !y = pubKeyParam key "y"

-- | Initialize a DSA public key using arguments p, q, g and y.
newDSAPubKey :: HasCallStack => MPI -> MPI -> MPI -> MPI -> PubKey
{-# INLINABLE newDSAPubKey  #-}
newDSAPubKey p q g y =
    unsafeWithMPI p $ \ p' ->
    withMPI q $ \ q' ->
    withMPI g $ \ g' ->
    withMPI y $ \ y' ->
        PubKey <$> newBotanStruct
            (\ key -> botan_pubkey_load_dsa key p' q' g' y')
            botan_pubkey_destroy

--------------------------------
-- ElGamal specific functions --
--------------------------------

-- | Get ElGamal parameters
--
-- * Set p, g to group parameters
-- * Set x to the private key
--
getElGamalPrivParams :: PrivKey
                 -> (MPI, MPI, MPI)   -- ^ (p, g, x)
{-# INLINABLE getElGamalPrivParams  #-}
getElGamalPrivParams key = (p, g, x)
  where
    !p = privKeyParam key "p"
    !g = privKeyParam key "g"
    !x = privKeyParam key "x"

newElGamalPrivKey :: HasCallStack => MPI -> MPI -> MPI -> PrivKey
{-# INLINABLE newElGamalPrivKey  #-}
newElGamalPrivKey p g x =
    unsafeWithMPI p $ \ p' ->
    withMPI g $ \ g' ->
    withMPI x $ \ x' ->
        PrivKey <$> newBotanStruct
            (\ key -> botan_privkey_load_elgamal key p' g' x')
            botan_privkey_destroy

-- | Get ElGamal parameters
--
-- * Set p, g to group parameters
-- * Set y to the public key
--
getElGamalPubParams :: PubKey
                    -> (MPI, MPI, MPI)   -- ^ (p, g, y)
{-# INLINABLE getElGamalPubParams  #-}
getElGamalPubParams key = (p, g, y)
  where
    !p = pubKeyParam key "p"
    !g = pubKeyParam key "g"
    !y = pubKeyParam key "y"

newElGamalPubKey :: HasCallStack => MPI -> MPI -> MPI -> PubKey
{-# INLINABLE newElGamalPubKey  #-}
newElGamalPubKey p g y =
    unsafeWithMPI p $ \ p' ->
    withMPI g $ \ g' ->
    withMPI y $ \ y' ->
        PubKey <$> newBotanStruct
                (\ key -> botan_pubkey_load_elgamal key p' g' y')
                botan_pubkey_destroy

---------------------------------------
-- Diffie-Hellman specific functions --
---------------------------------------

-- | Get Diffie-Hellman parameters
--
-- * Set p, g to group parameters
-- * Set x to the private key
--
getDHPrivParams :: PrivKey
                 -> (MPI, MPI, MPI)   -- ^ (p, g, x)
{-# INLINABLE getDHPrivParams  #-}
getDHPrivParams key = (p, g, x)
  where
    !p = privKeyParam key "p"
    !g = privKeyParam key "g"
    !x = privKeyParam key "x"

newDHPrivKey :: HasCallStack => MPI -> MPI -> MPI -> PrivKey
{-# INLINABLE newDHPrivKey  #-}
newDHPrivKey p g x = do
    unsafeWithMPI p $ \ p' -> withMPI g $ \ g' -> withMPI x $ \ x' ->
        PrivKey <$> newBotanStruct (\ key -> botan_privkey_load_dh key p' g' x') botan_privkey_destroy

-- | Get Diffie-Hellman parameters
--
-- * Set p, g to group parameters
-- * Set y to the public key
--
getDHPubParams :: PubKey
               -> (MPI, MPI, MPI)   -- ^ (p, g, y)
{-# INLINABLE getDHPubParams  #-}
getDHPubParams key = (p, g, y)
  where
    !p = pubKeyParam key "p"
    !g = pubKeyParam key "g"
    !y = pubKeyParam key "y"

newDHPubKey :: HasCallStack => MPI -> MPI -> MPI -> PubKey
{-# INLINABLE newDHPubKey  #-}
newDHPubKey p g y = do
    unsafeWithMPI p $ \ p' ->
        withMPI g $ \ g' ->
            withMPI y $ \ y' ->
                PubKey <$> newBotanStruct (\ pubKey -> botan_pubkey_load_dh pubKey p' g' y') botan_pubkey_destroy

----------------------------------------
-- Public Key Encryption / Decryption --
----------------------------------------

-- | Sets of allowed padding schemes for public key types.
--
-- The recommended values for eme is 'EME1_SHA1' or 'EME1_SHA256'.
-- If you need compatibility with protocols using the PKCS #1 v1.5 standard, you can also use 'EME_PKCS1_v1'5'.
data EMEPadding
    = EME_RAW
    | EME_PKCS1_v1'5
    | EME_OAEP HashType CBytes              -- ^ hash, label
    | EME_OAEP' HashType HashType CBytes    -- ^ hash, mask gen hash, labal

emeToCBytes :: EMEPadding -> CBytes
{-# INLINABLE emeToCBytes  #-}
emeToCBytes EME_RAW              = "Raw"
emeToCBytes EME_PKCS1_v1'5       = "PKCS1v15"
emeToCBytes (EME_OAEP  ht label)
    | CB.null label = CB.concat ["OAEP(", hashTypeToCBytes ht, ",MGF1)" ]
    | otherwise = CB.concat ["OAEP(", hashTypeToCBytes ht, ",MGF1,", label, ")"]

emeToCBytes (EME_OAEP' ht ht' label)
    | CB.null label =
        CB.concat ["OAEP(", hashTypeToCBytes ht, ",MGF1(", hashTypeToCBytes ht', "))"]
    | otherwise =
        CB.concat ["OAEP(", hashTypeToCBytes ht, ",MGF1(", hashTypeToCBytes ht', "),", label, ")"]

-- |  Encrypt a message, returning the ciphertext.
--
-- Though botan support DLIES and ECIES but only EME are exported via FFI, please use an algorithm that directly support eme encryption such as RSA and ElGamal.
--
pkEncrypt :: HasCallStack
          => PubKey -> EMEPadding -> RNG
          -> V.Bytes        -- ^ plaintext
          -> IO V.Bytes     -- ^ ciphertext
{-# INLINABLE pkEncrypt  #-}
pkEncrypt pubKey padding = encrypt_ pubKey (emeToCBytes padding)

-- |  Encrypt a message using SM2, returning the ciphertext.
sm2Encrypt :: HasCallStack
           => PubKey -> HashType -> RNG
           -> V.Bytes        -- ^ plaintext
           -> IO V.Bytes     -- ^ ciphertext
{-# INLINABLE sm2Encrypt  #-}
sm2Encrypt pubKey ht = encrypt_ pubKey (hashTypeToCBytes ht)

encrypt_ :: HasCallStack => PubKey -> CBytes -> RNG -> V.Bytes -> IO V.Bytes
{-# INLINABLE encrypt_  #-}
encrypt_ pubKey param rng ptext = do
    encryptor <-
        withPubKey pubKey $ \ pubKey' ->
        CB.withCBytesUnsafe param $ \ param' ->
            newBotanStruct
                (\ op -> botan_pk_op_encrypt_create op pubKey' param' 0) -- Flags should be 0 in this version.
                botan_pk_op_encrypt_destroy

    withBotanStruct encryptor $ \ op -> do
        let ptextLen = fromIntegral (V.length ptext)
        (len, _) <- allocPrimUnsafe @CSize $ \ ret ->
            throwBotanIfMinus_ (botan_pk_op_encrypt_output_length op ptextLen ret)
        withRNG rng $ \ rng' ->
            withPrimVectorUnsafe ptext $ \ ptext' ptextOff' ptextLen' ->
            allocBotanBufferUnsafe (fromIntegral len) $ \ out len' ->
                hs_botan_pk_op_encrypt op rng' out len' ptext' ptextOff' ptextLen'

-- |  Decrypt a message, returning the plaintext.
--
-- Though botan support DLIES and ECIES but only EME are exported via FFI, please use an algorithm that directly support decryption such as 'RSA' and 'ElGamal'.
--
pkDecrypt :: HasCallStack => PrivKey -> EMEPadding
          -> V.Bytes        -- ^ ciphertext
          -> V.Bytes        -- ^ plaintext
{-# INLINABLE pkDecrypt  #-}
pkDecrypt pubKey padding = decrypt_ pubKey (emeToCBytes padding)

-- |  Decrypt a message using SM2, returning the plaintext.
sm2Decrypt :: HasCallStack => PrivKey -> HashType
           -> V.Bytes        -- ^ plaintext
           -> V.Bytes     -- ^ ciphertext
{-# INLINABLE sm2Decrypt  #-}
sm2Decrypt privKey ht = decrypt_ privKey (hashTypeToCBytes ht)

decrypt_ :: HasCallStack => PrivKey -> CBytes -> V.Bytes -> V.Bytes
{-# INLINABLE decrypt_  #-}
decrypt_ key param ctext = unsafePerformIO $ do
    decryptor <-
        withPrivKey key $ \ key' ->
        CB.withCBytesUnsafe param $ \ param' ->
            newBotanStruct
                (\ op -> botan_pk_op_decrypt_create op key' param' 0) -- Flags should be 0 in this version.
                botan_pk_op_decrypt_destroy

    withBotanStruct decryptor $ \ op -> do
        let ctextLen = fromIntegral (V.length ctext)
        (len, _) <- allocPrimUnsafe @CSize $ \ ret ->
            throwBotanIfMinus_ (botan_pk_op_decrypt_output_length op ctextLen ret)
        withPrimVectorUnsafe ctext $ \ ctext' ctextOff' ctextLen' ->
            allocBotanBufferUnsafe (fromIntegral len) $ \ out len' ->
                hs_botan_pk_op_decrypt op out len' ctext' ctextOff' ctextLen'

--------------------------
-- Signature Generation --
--------------------------

-- |  Currently available values for 'EMSA', examples are “EMSA1(SHA-1)” and “EMSA4(SHA-256)”.
--
-- Currently available values for 'EMSA' include EMSA1, EMSA2, EMSA3, EMSA4, and Raw. All of them, except Raw, take a parameter naming a message digest function to hash the message with. The Raw encoding signs the input directly; if the message is too big, the signing operation will fail. Raw is not useful except in very specialized applications.
-- For RSA, use EMSA4 (also called PSS) unless you need compatibility with software that uses the older PKCS #1 v1.5 standard, in which case use EMSA3 (also called “EMSA-PKCS1-v1_5”). For DSA, ECDSA, ECKCDSA, ECGDSA and GOST 34.10-2001 you should use EMSA1.
--
data EMSA
    = EMSA1 HashType
    | EMSA2 HashType
    | EMSA3_RAW (Maybe HashType)
    | EMSA3 HashType
    | EMSA4_Raw HashType (Maybe Int)            -- ^ hash, salt size
    | EMSA4 HashType (Maybe Int)                -- ^ hash, salt size
    | ISO_9796_DS2 HashType Bool (Maybe Int)    -- ^ hash, implicit, salt size
    | ISO_9796_DS3 HashType Bool                -- ^ hash, implicit
    | EMSA_Raw

emsaToCBytes :: EMSA -> CBytes
{-# INLINABLE emsaToCBytes  #-}
emsaToCBytes (EMSA1 ht) = CB.concat ["EMSA1(", hashTypeToCBytes ht, ")"]
emsaToCBytes (EMSA3_RAW (Just ht)) =
    CB.concat ["EMSA3(Raw,", hashTypeToCBytes ht, ")"]
emsaToCBytes (EMSA3_RAW _) = "EMSA3(Raw)"
emsaToCBytes (EMSA3 ht) = CB.concat ["EMSA3(", hashTypeToCBytes ht, ")"]
emsaToCBytes (EMSA4_Raw ht (Just siz)) =
    CB.concat ["EMSA4_Raw(", hashTypeToCBytes ht, ",MGF1,", CB.fromText (T.toText siz) , ")"]
emsaToCBytes (EMSA4_Raw ht _) =
    CB.concat ["EMSA4_Raw(", hashTypeToCBytes ht, ")"]
emsaToCBytes (EMSA4 ht (Just siz)) =
    CB.concat ["EMSA4(", hashTypeToCBytes ht, ",MGF1,", CB.fromText (T.toText siz) , ")"]
emsaToCBytes (EMSA4 ht _) =
    CB.concat ["EMSA4(", hashTypeToCBytes ht, ")"]
emsaToCBytes (ISO_9796_DS2 ht imp (Just siz)) =
    CB.concat [ "ISO_9796_DS2(", hashTypeToCBytes ht
              , if imp then ",imp," else ",exp,"
              , CB.fromText (T.toText siz) , ")"]
emsaToCBytes (ISO_9796_DS2 ht imp _) =
    CB.concat [ "ISO_9796_DS2(", hashTypeToCBytes ht
              , if imp then ",imp)" else ",exp)"
              ]
emsaToCBytes (ISO_9796_DS3 ht imp) =
    CB.concat [ "ISO_9796_DS3(", hashTypeToCBytes ht
              , if imp then ",imp)" else ",exp)"
              ]
emsaToCBytes (EMSA2 ht) = CB.concat ["EMSA2(", hashTypeToCBytes ht, ")"]
emsaToCBytes EMSA_Raw = "Raw"

-- The format defaults to IEEE_1363 which is the only available format for RSA. For DSA, ECDSA, ECGDSA and ECKCDSA you can also use DER_SEQUENCE, which will format the signature as an ASN.1 SEQUENCE value.
data SignFmt = DER_SEQUENCE | IEEE_1363
    deriving (Eq, Ord, Show, Generic)
    deriving anyclass T.Print

signFmtToFlag :: SignFmt -> Word32
{-# INLINABLE signFmtToFlag  #-}
signFmtToFlag DER_SEQUENCE = 1
signFmtToFlag IEEE_1363    = 0

data Signer = Signer
    { signerStruct :: {-# UNPACK #-} !BotanStruct
    , signerName   :: {-# UNPACK #-} !CBytes
    , signerFmt    :: !SignFmt
    , signerSiz    :: {-# UNPACK #-} !Int           -- ^ output length
    }
    deriving (Show, Generic)
    deriving anyclass T.Print

newSigner :: HasCallStack => PrivKey -> EMSA -> SignFmt -> IO Signer
{-# INLINABLE newSigner  #-}
newSigner key emsa fmt = do
    let name = emsaToCBytes emsa
    withPrivKey key $ \ key' ->
        CB.withCBytesUnsafe name $ \ arg -> do
            op <- newBotanStruct
                (\ ret -> botan_pk_op_sign_create ret key' arg (signFmtToFlag fmt))
                botan_pk_op_sign_destroy
            siz <- withBotanStruct op $ \ op' ->
                fst <$> allocPrimUnsafe @CSize (\ siz' ->
                    throwBotanIfMinus_ $ botan_pk_op_sign_output_length op' siz')
            return (Signer op name fmt (fromIntegral siz))

updateSigner :: HasCallStack => Signer -> V.Bytes -> IO ()
{-# INLINABLE updateSigner  #-}
updateSigner (Signer op _ _ _) msg =
    withBotanStruct op $ \ op' ->
    withPrimVectorUnsafe msg $ \ m moff mlen ->
        throwBotanIfMinus_ (hs_botan_pk_op_sign_update op' m moff mlen)

-- | Produce a signature over all of the bytes passed to 'Signer'.
-- Afterwards, the sign operator is reset and may be used to sign a new message.
finalSigner :: HasCallStack => Signer -> RNG -> IO V.Bytes
{-# INLINABLE finalSigner  #-}
finalSigner (Signer op _ _ siz) rng =
    withBotanStruct op $ \ op' ->
    withRNG rng $ \ rng' ->
    allocBotanBufferUnsafe siz $ botan_pk_op_sign_finish op' rng'

-- | Trun 'Signer' to a 'V.Bytes' sink, update 'Signer' by write bytes to the sink.
--
sinkToSigner :: HasCallStack => HasCallStack => Signer -> Sink V.Bytes
{-# INLINABLE sinkToSigner #-}
sinkToSigner h = \ k mbs -> case mbs of
    Just bs -> updateSigner h bs
    _       -> k EOF

-- | Directly sign a message, with system RNG.
sign :: HasCallStack
     => PrivKey -> EMSA -> SignFmt
     -> V.Bytes         -- ^ input
     -> IO V.Bytes      -- ^ signature
{-# INLINABLE sign #-}
sign key emsa fmt inp = do
    m <- newSigner key emsa fmt
    updateSigner m inp
    finalSigner m =<< getRNG

-- | Directly compute a chunked message's mac with system RNG.
signChunks :: HasCallStack
           => PrivKey -> EMSA -> SignFmt
           -> [V.Bytes]
           -> IO V.Bytes
{-# INLINABLE signChunks #-}
signChunks key emsa fmt inps = do
    m <- newSigner key emsa fmt
    mapM_ (updateSigner m) inps
    finalSigner m =<< getRNG

----------------------------
-- Signature Verification --
----------------------------

data Verifier = Verifier
    { verifierStruct :: {-# UNPACK #-} !BotanStruct
    , verifierName   :: {-# UNPACK #-} !CBytes
    , verifierFmt    :: !SignFmt
    }
    deriving (Show, Generic)
    deriving anyclass T.Print

newVerifier :: HasCallStack => PubKey -> EMSA -> SignFmt -> IO Verifier
{-# INLINABLE newVerifier  #-}
newVerifier pubKey emsa fmt = do
    let name = emsaToCBytes emsa
    withPubKey pubKey $ \ pubKey' ->
        CB.withCBytesUnsafe name $ \ arg -> do
            op <- newBotanStruct
                (\ ret -> botan_pk_op_verify_create ret pubKey' arg (signFmtToFlag fmt))
                botan_pk_op_verify_destroy
            return (Verifier op name fmt)

updateVerifier :: HasCallStack => Verifier -> V.Bytes -> IO ()
{-# INLINABLE updateVerifier  #-}
updateVerifier (Verifier op _ _) msg = do
    withBotanStruct op $ \ op' ->
        withPrimVectorUnsafe msg $ \ msg' off len ->
            throwBotanIfMinus_ $ hs_botan_pk_op_verify_update op' msg' off len

finalVerifier :: HasCallStack => Verifier -> V.Bytes -> IO Bool
{-# INLINABLE finalVerifier  #-}
finalVerifier (Verifier op _ _) msg =
    withBotanStruct op $ \ op' ->
    withPrimVectorUnsafe msg $ \ msg' off len -> do
        r <- throwBotanIfMinus $ hs_botan_pk_op_verify_finish op' msg' off len
        print r
        return $ r == BOTAN_FFI_SUCCESS
--    BOTAN_FFI_SUCCESS = 0,
--    BOTAN_FFI_INVALID_VERIFIER = 1

-- | Trun 'Verifier' to a 'V.Bytes' sink, update 'Verifier' by write bytes to the sink.
--
sinkToVerifier :: HasCallStack => Verifier -> Sink V.Bytes
{-# INLINABLE sinkToVerifier  #-}
sinkToVerifier h = \ k mbs -> case mbs of
    Just bs -> updateVerifier h bs
    _       -> k EOF

-- | Directly sign a message.
verify :: HasCallStack
       => PubKey -> EMSA -> SignFmt
       -> V.Bytes  -- ^ input
       -> V.Bytes  -- ^ signature
       -> Bool
{-# INLINABLE verify #-}
verify key emsa fmt inp sig = unsafePerformIO $ do
    m <- newVerifier key emsa fmt
    updateVerifier m inp
    finalVerifier m sig

-- | Directly compute a chunked message's mac.
verifyChunks :: HasCallStack
           => PubKey -> EMSA -> SignFmt
           -> [V.Bytes]
           -> V.Bytes           -- ^ signature
           -> Bool
{-# INLINABLE verifyChunks  #-}
verifyChunks key emsa fmt inps sig = unsafePerformIO $ do
    m <- newVerifier key emsa fmt
    mapM_ (updateVerifier m) inps
    finalVerifier m sig

-------------------
-- Key Agreement --
-------------------

-- | Key agreement object.
data KeyAgreement = KeyAgreement
    { keyAgreementStruct :: {-# UNPACK #-} !BotanStruct
    , keyAgreementSize   :: {-# UNPACK #-} !Int
    }
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Create a new key agreement operation with a given key pair and KDF algorithm.
--
-- Please use a key type that support key agreement, such as 'DH', 'ECDH', or 'Curve25519'.
--
newKeyAgreement :: HasCallStack => PrivKey -> KDFType -> IO KeyAgreement
{-# INLINABLE newKeyAgreement  #-}
newKeyAgreement key kdf =
    withPrivKey key $ \ key' ->
    CB.withCBytesUnsafe (kdfTypeToCBytes kdf) $ \ kdf' -> do
        op <- newBotanStruct
            (\ op -> botan_pk_op_key_agreement_create op key' kdf' 0) -- Flags should be 0 in this version.
            botan_pk_op_key_agreement_destroy
        siz <- withBotanStruct op $ \ op' ->
            fst <$> allocPrimUnsafe @CSize (\ siz' ->
                throwBotanIfMinus_ $ botan_pk_op_key_agreement_size op' siz')
        return (KeyAgreement op (fromIntegral siz))

exportKeyAgreementPublic :: HasCallStack => PrivKey -> IO V.Bytes
{-# INLINABLE exportKeyAgreementPublic  #-}
exportKeyAgreementPublic key =
    withPrivKey key $ \ key' ->
    allocBotanBufferUnsafe 128 $ botan_pk_op_key_agreement_export_public key'

-- | How key agreement works is that you trade public values with some other party, and then each of you runs a computation with the other’s value and your key (this should return the same result to both parties).
keyAgree ::
    HasCallStack =>
    KeyAgreement ->
    -- | other key
    V.Bytes ->
    -- | salt
    V.Bytes ->
    IO V.Bytes
{-# INLINABLE keyAgree  #-}
keyAgree (KeyAgreement op siz) others salt =
    withBotanStruct op $ \ op' ->
    withPrimVectorUnsafe others $ \ others' others_off others_len ->
    withPrimVectorUnsafe salt $ \ salt' salt_off salt_len ->
    allocBotanBufferUnsafe siz $ \ ret len ->
        hs_botan_pk_op_key_agreement op' ret len others'
            others_off others_len salt' salt_off salt_len
