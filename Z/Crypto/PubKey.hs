{-|
Module      : Z.Crypto.PubKey
Description : Public Key Cryptography
Copyright   : Dong Han, 2021
              AnJie Dong, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

This module is used for Public Key Cryptography.
Public key cryptography (also called asymmetric cryptography) is a collection of techniques allowing for encryption, signatures, and key agreement.
-}

module Z.Crypto.PubKey (
  -- * Asymmetric cryptography algorithms
    KeyType(..), pattern RSADefault, pattern McElieceDefault, pattern XMSSDefault
  , ECCType(..), DLType(..)
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

-- | Public Key Cryptography Algorithms.
data KeyType
    = Curve25519
    | -- | RSA key of the given size, namely n bits
        RSA Word32
      -- | McEliece is a cryptographic scheme based on error correcting codes which is thought to be resistant to quantum computers. See <mceliece https://botan.randombit.net/handbook/api_ref/pubkey.html#mceliece>.
    | McEliece Word32 -- ^ n
               Word32 -- ^ t
      -- | eXtended Merkle Signature Scheme, see <xmss https://botan.randombit.net/handbook/api_ref/pubkey.html#extended-merkle-signature-scheme-xmss>
    | XMSS XMSSType
      -- | Ed25519 high-speed high-security signatures
    | Ed25519
      -- | Elliptic-curve cryptography, see 'ECCType'
    | ECC ECCType ECGroup
      -- | Asymmetric algorithm based on the discrete logarithm problem, see 'DLType'
    | DL DLType DLGroup

keyTypeToCBytes :: KeyType -> (CBytes, CBytes)
keyTypeToCBytes keyType' = case keyType' of
    Curve25519 -> ("Curve25519", "")
    RSA bits -> ("RSA", CB.buildCBytes $ B.int bits)
    McEliece n t -> ("McEliece", CB.buildCBytes $ B.int n >> B.char8 ',' >> B.int t)
    XMSS xmss -> ("XMSS", xmss)
    Ed25519 -> ("Ed25519", "")
    ECC ecc grp -> (eccToCBytes ecc, grp)
    DL dl grp -> (dlToCBytes dl, grp)

-- | Default RSA Key type(3072 bits).
pattern RSADefault :: KeyType
pattern RSADefault = RSA 3072

-- | Default McEliece key type.
pattern McElieceDefault :: KeyType
pattern McElieceDefault = McEliece 2960 57

-- | A type wrapper.
type XMSSType = CBytes

pattern XMSSDefault :: KeyType
pattern XMSSDefault = XMSS XMSS_SHA2_10_512

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

-- | Algorithms based on elliptic curve.
data ECCType
    = ECDSA | ECDH | ECKCDSA | ECGDSA | SM2 | SM2_Sig
    | SM2_Enc | GOST_34_10 | GOST_34_10_2012_256 | GOST_34_10_2012_512

eccToCBytes :: ECCType -> CBytes
eccToCBytes = \ case
    ECDSA -> "ECDSA"
    ECDH -> "ECDH"
    ECKCDSA -> "ECKCDSA"
    ECGDSA -> "ECGDSA"
    SM2 -> "SM2"
    SM2_Sig -> "SM2_Sig"
    SM2_Enc -> "SM2_Enc"
    GOST_34_10 -> "GOST-34.10"
    GOST_34_10_2012_256 -> "GOST-34.10-2012-256"
    GOST_34_10_2012_512 -> "GOST-34.10-2012-512"

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

-- | Discrete Logarithm
data DLType
    = DH        -- ^ Diffie-Hellman key exchange
    | DSA       -- ^ Digital Signature Algorithm
    | ElGamal

dlToCBytes :: DLType -> CBytes
dlToCBytes = \ case
    DH -> "DH"
    DSA -> "DSA"
    ElGamal -> "ElGamal"

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
withPrivKey (PrivKey key) = withBotanStruct key

-- | Creating a new key pair.
--
newKeyPair ::
    -- | Algorithm name and some algorithm specific arguments.
    KeyType ->
    RNG ->
    IO (PrivKey, PubKey)
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
newPrivKey ::
    -- | Algorithm name and some algorithm specific arguments.
    KeyType ->
    RNG ->
    IO PrivKey
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
loadPrivKey ::
    RNG ->
    V.Bytes ->
    -- | Password.
    CBytes ->
    IO PrivKey
loadPrivKey rng buf passwd =
    withRNG rng $ \ rng' ->
    withPrimVectorUnsafe buf $ \ buf' off len ->
    CB.withCBytesUnsafe passwd $ \ passwd' ->
        PrivKey <$> newBotanStruct
            (\ key -> hs_botan_privkey_load key rng' buf' off len passwd')
            botan_privkey_destroy

-- | Get the algorithm name of a private key.
privKeyAlgoName :: PrivKey -> IO V.Bytes
privKeyAlgoName key =
    withPrivKey key $ allocBotanBufferUnsafe 16 . botan_privkey_algo_name

-- | Export a private key in DER binary format.
exportPrivKeyDER :: HasCallStack => PrivKey -> V.Bytes
{-# INLINE exportPrivKeyDER #-}
exportPrivKeyDER key = unsafePerformIO $
    withPrivKey key $ \ key' ->
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export key' buf siz 0

-- | Export a private key in PEM textual format.
exportPrivKeyPEM :: HasCallStack => PrivKey -> T.Text
{-# INLINE exportPrivKeyPEM #-}
exportPrivKeyPEM key = unsafePerformIO $
    withPrivKey key $ \ key' ->
    allocBotanBufferUTF8Unsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export key' buf siz 1

-- | Export a private key with password.
exportPrivKeyEncryptedDER :: PrivKey -> RNG
                          -> CBytes        -- ^ password
                          -> IO V.Bytes
exportPrivKeyEncryptedDER key rng pwd =
    withPrivKey key $ \ key' ->
    withRNG rng $ \ rng' ->
    CB.withCBytesUnsafe pwd $ \ pwd' ->
    CB.withCBytesUnsafe "" $ \ pbe' ->   -- currently ignored
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export_encrypted key' buf siz rng' pwd' pbe' 0

-- | Export a private key with password in PEM textual format.
exportPrivKeyEncryptedPEM :: PrivKey -> RNG
                          -> CBytes        -- ^ password
                          -> IO T.Text
exportPrivKeyEncryptedPEM key rng pwd =
    withPrivKey key $ \ key' ->
    withRNG rng $ \ rng' ->
    CB.withCBytesUnsafe pwd $ \ pwd' ->
    CB.withCBytesUnsafe "" $ \ pbe' ->   -- currently ignored
    allocBotanBufferUTF8Unsafe V.smallChunkSize $ \ buf siz ->
    botan_privkey_export_encrypted key' buf siz rng' pwd' pbe' 1

-- | Export a public key from a given key pair.
privKeyToPubKey :: PrivKey -> PubKey
{-# INLINE privKeyToPubKey #-}
privKeyToPubKey (PrivKey priv) = unsafePerformIO $ do
    withBotanStruct priv $ \ priv' ->
        PubKey <$> newBotanStruct (`botan_privkey_export_pubkey` priv') botan_privkey_destroy

-- | Read an algorithm specific field from the key pair object.
privKeyParam :: HasCallStack
             => PrivKey      -- ^ key
             -> CBytes       -- ^ field name
             -> MPI
{-# INLINE privKeyParam #-}
privKeyParam key name =
    unsafeNewMPI $ \ mp ->
    withPrivKey key $ \ key' -> do
    throwBotanIfMinus_ (CB.withCBytesUnsafe name (botan_privkey_get_field mp key'))

-- | A newtype wrapper.
newtype PubKey = PubKey BotanStruct
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass T.Print

-- | Pass 'PubKey' to FFI.
withPubKey :: HasCallStack
            => PubKey -> (BotanStructT -> IO r) -> IO r
withPubKey (PubKey key) = withBotanStruct key

-- | Load a publickey.
loadPubKey :: HasCallStack
           => V.Bytes -> IO PubKey
{-# INLINE loadPubKey #-}
loadPubKey buf = do
    withPrimVectorUnsafe buf $ \ buf' off len ->
        PubKey <$> newBotanStruct (\ pubKey -> hs_botan_pubkey_load pubKey buf' off len) botan_pubkey_destroy

-- | Export a public key in DER binary format..
exportPubKeyDER :: HasCallStack => PubKey -> V.Bytes
{-# INLINE exportPubKeyDER #-}
exportPubKeyDER pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_pubkey_export pubKey' buf siz 0

-- | Export a public key in PEM textual format.
exportPubKeyPEM :: HasCallStack => PubKey -> T.Text
{-# INLINE exportPubKeyPEM #-}
exportPubKeyPEM pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
    allocBotanBufferUTF8Unsafe V.smallChunkSize $ \ buf siz ->
    botan_pubkey_export pubKey' buf siz 1

-- | Get the algorithm name of a public key.
pubKeyAlgoName :: PubKey -> CBytes
{-# INLINE pubKeyAlgoName #-}
pubKeyAlgoName pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
        CB.fromBytes <$> allocBotanBufferUnsafe 16
            (botan_pubkey_algo_name pubKey')

-- | Estimate the strength of a public key.
estStrength :: PubKey -> Int
{-# INLINE estStrength #-}
estStrength pubKey = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' -> do
        (a, _) <- allocPrimUnsafe @CSize $ \ est ->
            throwBotanIfMinus_ (botan_pubkey_estimated_strength pubKey' est)
        return (fromIntegral a)

-- | Fingerprint a given publickey.
fingerPrintPubKey :: PubKey -> HashType -> V.Bytes
{-# INLINE fingerPrintPubKey #-}
fingerPrintPubKey pubKey ht = unsafePerformIO $
    withPubKey pubKey $ \ pubKey' ->
    CB.withCBytesUnsafe (hashTypeToCBytes ht) $ \ hash' ->
    allocBotanBufferUnsafe V.smallChunkSize $ \ buf siz ->
    botan_pubkey_fingerprint pubKey' hash' buf siz

-- | Read an algorithm specific field from the public key object.
pubKeyParam :: HasCallStack
                    => PubKey       -- ^ key
                    -> CBytes       -- ^ field name
                    -> MPI
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
getRSAPubParams key = (n, e)
  where
    !n = pubKeyParam key "n"
    !e = pubKeyParam key "e"

-- | Initialize a RSA key pair using arguments p, q, and e.
newRSAPrivKey :: MPI -> MPI -> MPI -> PrivKey
newRSAPrivKey p q e =
    unsafeWithMPI p $ \ p' ->
    withMPI q $ \ q' ->
    withMPI e $ \ e' ->
        PrivKey <$> newBotanStruct
            (\ key -> botan_privkey_load_rsa key p' q' e')
            botan_privkey_destroy

-- | Initialize a public RSA key using arguments n and e.
newRSAPubKey :: MPI -> MPI -> PubKey
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
getDSAPrivParams key = (p, q, g, x)
  where
    !p = privKeyParam key "p"
    !q = privKeyParam key "q"
    !g = privKeyParam key "g"
    !x = privKeyParam key "x"

-- | Initialize a DSA key pair using arguments p, q, g and x.
newDSAPrivKey :: MPI -> MPI -> MPI -> MPI -> PrivKey
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
getDSAPubParams key = (p, q, g, y)
  where
    !p = pubKeyParam key "p"
    !q = pubKeyParam key "q"
    !g = pubKeyParam key "g"
    !y = pubKeyParam key "y"

-- | Initialize a DSA public key using arguments p, q, g and y.
newDSAPubKey :: MPI -> MPI -> MPI -> MPI -> PubKey
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
getElGamalPrivParams key = (p, g, x)
  where
    !p = privKeyParam key "p"
    !g = privKeyParam key "g"
    !x = privKeyParam key "x"

newElGamalPrivKey :: MPI -> MPI -> MPI -> PrivKey
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
getElGamalPubParams key = (p, g, y)
  where
    !p = pubKeyParam key "p"
    !g = pubKeyParam key "g"
    !y = pubKeyParam key "y"

newElGamalPubKey :: MPI -> MPI -> MPI -> PubKey
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
getDHPrivParams key = (p, g, x)
  where
    !p = privKeyParam key "p"
    !g = privKeyParam key "g"
    !x = privKeyParam key "x"

newDHPrivKey :: MPI -> MPI -> MPI -> PrivKey
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
getDHPubParams key = (p, g, y)
  where
    !p = pubKeyParam key "p"
    !g = pubKeyParam key "g"
    !y = pubKeyParam key "y"

newDHPubKey :: MPI -> MPI -> MPI -> PubKey
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
-- Though botan support DLIES and ECIES but only EME are exported via FFI, please use an algorithm that directly
-- support encryption such as RSA and ElGamal.
--
pkEncrypt :: PubKey -> EMEPadding -> RNG
          -> V.Bytes        -- ^ plaintext
          -> IO V.Bytes     -- ^ ciphertext
pkEncrypt pubKey padding rng ptext = do
    let paddingStr = emeToCBytes padding
    encryptor <-
        withPubKey pubKey $ \ pubKey' ->
        CB.withCBytesUnsafe paddingStr $ \ padding' ->
            newBotanStruct
                (\ op -> botan_pk_op_encrypt_create op pubKey' padding' 0) -- Flags should be 0 in this version.
                botan_pk_op_encrypt_destroy

    withBotanStruct encryptor $ \ op -> do
        let ptextLen = fromIntegral (V.length ptext)
        (len, _) <- allocPrimUnsafe @CSize $ \ ret ->
            throwBotanIfMinus_ (botan_pk_op_encrypt_output_length op ptextLen ret)
        withRNG rng $ \ rng' ->
            withPrimVectorUnsafe ptext $ \ ptext' ptextOff' ptextLen' ->
            allocBotanBufferUnsafe (fromIntegral len) $ \ out len' ->
                hs_botan_pk_op_encrypt op rng' out len' ptext' ptextOff' ptextLen'

-- |  Decrypt a message, returning the ciphertext.
--
-- Though botan support DLIES and ECIES but only EME are exported via FFI, please use an algorithm that directly
-- support decryption such as RSA and ElGamal.
--
pkDecrypt :: PrivKey -> EMEPadding
          -> V.Bytes        -- ^ ciphertext
          -> V.Bytes        -- ^ plaintext
pkDecrypt key padding ctext = unsafePerformIO $ do
    let paddingStr = emeToCBytes padding
    decryptor <-
        withPrivKey key $ \ key' ->
        CB.withCBytesUnsafe paddingStr $ \ padding' ->
            newBotanStruct
                (\ op -> botan_pk_op_decrypt_create op key' padding' 0) -- Flags should be 0 in this version.
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

newSigner :: PrivKey -> EMSA -> SignFmt -> IO Signer
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

updateSigner :: Signer -> V.Bytes -> IO ()
updateSigner (Signer op _ _ _) msg =
    withBotanStruct op $ \ op' ->
    withPrimVectorUnsafe msg $ \ m moff mlen ->
        throwBotanIfMinus_ (hs_botan_pk_op_sign_update op' m moff mlen)

-- | Produce a signature over all of the bytes passed to 'Signer'.
-- Afterwards, the sign operator is reset and may be used to sign a new message.
finalSigner :: Signer -> RNG -> IO V.Bytes
finalSigner (Signer op _ _ siz) rng =
    withBotanStruct op $ \ op' ->
    withRNG rng $ \ rng' ->
    allocBotanBufferUnsafe siz $ botan_pk_op_sign_finish op' rng'

-- | Trun 'Signer' to a 'V.Bytes' sink, update 'Signer' by write bytes to the sink.
--
sinkToSigner :: HasCallStack => Signer -> Sink V.Bytes
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

newVerifier :: PubKey -> EMSA -> SignFmt -> IO Verifier
newVerifier pubKey emsa fmt = do
    let name = emsaToCBytes emsa
    withPubKey pubKey $ \ pubKey' ->
        CB.withCBytesUnsafe name $ \ arg -> do
            op <- newBotanStruct
                (\ ret -> botan_pk_op_verify_create ret pubKey' arg (signFmtToFlag fmt))
                botan_pk_op_verify_destroy
            return (Verifier op name fmt)

updateVerifier :: Verifier -> V.Bytes -> IO ()
updateVerifier (Verifier op _ _) msg = do
    withBotanStruct op $ \ op' ->
        withPrimVectorUnsafe msg $ \ msg' off len ->
            throwBotanIfMinus_ $ hs_botan_pk_op_verify_update op' msg' off len

finalVerifier :: Verifier
              -> V.Bytes
              -> IO Bool
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
{-# INLINABLE sinkToVerifier #-}
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
{-# INLINABLE verifyChunks #-}
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
-- Use a key type that support key agreement, such as 'DH' or 'ECDH',
-- Botan implements the following key agreement methods:
-- * ECDH over GF(p) Weierstrass curves
-- * ECDH over x25519
-- * DH over prime fields
-- * McEliece
-- * NewHope
--
newKeyAgreement :: PrivKey -> KDFType -> IO KeyAgreement
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

exportKeyAgreementPublic :: PrivKey -> IO V.Bytes
exportKeyAgreementPublic key =
    withPrivKey key $ \ key' ->
    allocBotanBufferUnsafe 128 $ botan_pk_op_key_agreement_export_public key'

-- | How key agreement works is that you trade public values with some other party, and then each of you runs a computation with the other’s value and your key (this should return the same result to both parties).
keyAgree ::
    KeyAgreement ->
    -- | other key
    V.Bytes ->
    -- | salt
    V.Bytes ->
    IO V.Bytes
keyAgree (KeyAgreement op siz) others salt =
    withBotanStruct op $ \ op' ->
    withPrimVectorUnsafe others $ \ others' others_off others_len ->
    withPrimVectorUnsafe salt $ \ salt' salt_off salt_len ->
    allocBotanBufferUnsafe siz $ \ ret len ->
        hs_botan_pk_op_key_agreement op' ret len others'
            others_off others_len salt' salt_off salt_len
