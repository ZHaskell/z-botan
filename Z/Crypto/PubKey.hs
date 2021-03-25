-- |
-- This module is used for Public Key Cryptography.
-- Public key cryptography (also called asymmetric cryptography) is a collection of techniques allowing for encryption, signatures, and key agreement.
module Z.Crypto.PubKey where

import Data.Word (Word32)
import Z.Botan.Exception (throwBotanIfMinus_)
import Z.Botan.FFI
  ( BotanStruct,
    botan_pk_op_decrypt_create,
    botan_pk_op_decrypt_destroy,
    botan_pk_op_decrypt_output_length,
    botan_pk_op_encrypt_create,
    botan_pk_op_encrypt_destroy,
    botan_pk_op_encrypt_output_length,
    botan_pk_op_key_agreement_create,
    botan_pk_op_key_agreement_destroy,
    botan_pk_op_key_agreement_export_public,
    botan_pk_op_sign_create,
    botan_pk_op_sign_destroy,
    botan_pk_op_sign_finish,
    botan_pk_op_sign_output_length,
    botan_pk_op_verify_create,
    botan_pk_op_verify_destroy,
    botan_privkey_create,
    botan_privkey_destroy,
    botan_privkey_export,
    botan_privkey_export_pubkey,
    botan_privkey_get_field,
    botan_privkey_load_dh,
    botan_privkey_load_dsa,
    botan_privkey_load_elgamal,
    botan_privkey_load_rsa,
    botan_privkey_rsa_get_d,
    botan_privkey_rsa_get_e,
    botan_privkey_rsa_get_n,
    botan_privkey_rsa_get_p,
    botan_privkey_rsa_get_q,
    botan_pubkey_algo_name,
    botan_pubkey_destroy,
    botan_pubkey_estimated_strength,
    botan_pubkey_fingerprint,
    botan_pubkey_get_field,
    botan_pubkey_load_dh,
    botan_pubkey_load_dsa,
    botan_pubkey_load_elgamal,
    botan_pubkey_load_rsa,
    botan_pubkey_rsa_get_e,
    botan_pubkey_rsa_get_n,
    hs_botan_pk_op_decrypt,
    hs_botan_pk_op_encrypt,
    hs_botan_pk_op_key_agreement,
    hs_botan_pk_op_sign_update,
    hs_botan_pk_op_verify_finish,
    hs_botan_pk_op_verify_update,
    hs_botan_privkey_load,
    hs_botan_pubkey_load,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto (HashType, hashTypeToCBytes)
import Z.Crypto.MPI (MPI, unsafeNewMPI, unsafeWithMPI, withMPI)
import Z.Crypto.RNG (RNG, withRNG)
import qualified Z.Data.Builder as B
import Z.Data.CBytes (CBytes, append, buildCBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign
  ( CSize,
    allocPrimUnsafe,
    allocPrimVectorUnsafe,
    withPrimVectorUnsafe,
  )

---------------
-- Key Types --
---------------

-- | A newtype wrapper.
newtype PrivKeyType = PrivKeyType KeyType

-- | A newtype wrapper.
newtype PubKeyType = PubKeyType KeyType

-- | The public and private keys are represented by the type `KeyType`. Two newtype wrappers are given.
data KeyType
  = Curve25519
  | -- | an RSA key of the given size, namely n bits
    RSA Word32
  | McEliece
      Word32
      -- ^ n
      Word32
      -- ^ t
  | XMSS XMSSType
  | Ed25519
  | ECC ECCType ECGrp
  | DL DLType DLGrp

pattern RSADefault :: KeyType
pattern RSADefault = RSA 3072

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

data ECCType = ECDSA | ECDH | ECKCDSA | ECGDSA | SM2 | SM2_Sig | SM2_Enc | GOST_34_10 | GOST_34_10_2012_256 | GOST_34_10_2012_512

eccToCBytes :: ECCType -> CBytes
eccToCBytes = \case
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

-- | A type wrapper.
type ECGrp = CBytes

-- TODO: default_ec_group_for

pattern Secp160k1 :: ECGrp
pattern Secp160k1 = "secp160k1"

pattern Secp160r1 :: ECGrp
pattern Secp160r1 = "secp160r1"

pattern Secp160r2 :: ECGrp
pattern Secp160r2 = "secp160r2"

pattern Secp192k1 :: ECGrp
pattern Secp192k1 = "secp192k1"

pattern Secp192r1 :: ECGrp
pattern Secp192r1 = "secp192r1"

pattern Secp224k1 :: ECGrp
pattern Secp224k1 = "secp224k1"

pattern Secp224r1 :: ECGrp
pattern Secp224r1 = "secp224r1"

pattern Secp256k1 :: ECGrp
pattern Secp256k1 = "secp256k1"

pattern Secp256r1 :: ECGrp
pattern Secp256r1 = "secp256r1"

pattern Secp384r1 :: ECGrp
pattern Secp384r1 = "secp384r1"

pattern Secp521r1 :: ECGrp
pattern Secp521r1 = "secp521r1"

pattern Brainpool160r1 :: ECGrp
pattern Brainpool160r1 = "brainpool160r1"

pattern Brainpool192r1 :: ECGrp
pattern Brainpool192r1 = "brainpool192r1"

pattern Brainpool224r1 :: ECGrp
pattern Brainpool224r1 = "brainpool224r1"

pattern Brainpool256r1 :: ECGrp
pattern Brainpool256r1 = "brainpool256r1"

pattern Brainpool320r1 :: ECGrp
pattern Brainpool320r1 = "brainpool320r1"

pattern Brainpool384r1 :: ECGrp
pattern Brainpool384r1 = "brainpool384r1"

pattern Brainpool512r1 :: ECGrp
pattern Brainpool512r1 = "brainpool512r1"

pattern X962_p192v2 :: ECGrp
pattern X962_p192v2 = "x962_p192v2"

pattern X962_p192v3 :: ECGrp
pattern X962_p192v3 = "x962_p192v3"

pattern X962_p239v1 :: ECGrp
pattern X962_p239v1 = "x962_p239v1"

pattern X962_p239v2 :: ECGrp
pattern X962_p239v2 = "x962_p239v2"

pattern X962_p239v3 :: ECGrp
pattern X962_p239v3 = "x962_p239v3"

pattern Gost_256A :: ECGrp
pattern Gost_256A = "gost_256A"

pattern Gost_512A :: ECGrp
pattern Gost_512A = "gost_512A"

pattern Frp256v1 :: ECGrp
pattern Frp256v1 = "frp256v1"

pattern Sm2p256v1 :: ECGrp
pattern Sm2p256v1 = "sm2p256v1"

data DLType = DH | DSA | ElGamal

dlToCBytes :: DLType -> CBytes
dlToCBytes = \case
  DH -> "DH"
  DSA -> "DSA"
  ElGamal -> "ElGamal"

type DLGrp = CBytes

-- TODO: default_group

pattern FFDHE_IETF_2048 :: DLGrp
pattern FFDHE_IETF_2048 = "ffdhe/ietf/2048"

pattern FFDHE_IETF_3072 :: DLGrp
pattern FFDHE_IETF_3072 = "ffdhe/ietf/3072"

pattern FFDHE_IETF_4096 :: DLGrp
pattern FFDHE_IETF_4096 = "ffdhe/ietf/4096"

pattern FFDHE_IETF_6144 :: DLGrp
pattern FFDHE_IETF_6144 = "ffdhe/ietf/6144"

pattern FFDHE_IETF_8192 :: DLGrp
pattern FFDHE_IETF_8192 = "ffdhe/ietf/8192"

pattern MODP_IETF_1024 :: DLGrp
pattern MODP_IETF_1024 = "modp/ietf/1024"

pattern MODP_IETF_1536 :: DLGrp
pattern MODP_IETF_1536 = "modp/ietf/1536"

pattern MODP_IETF_2048 :: DLGrp
pattern MODP_IETF_2048 = "modp/ietf/2048"

pattern MODP_IETF_3072 :: DLGrp
pattern MODP_IETF_3072 = "modp/ietf/3072"

pattern MODP_IETF_4096 :: DLGrp
pattern MODP_IETF_4096 = "modp/ietf/4096"

pattern MODP_IETF_6144 :: DLGrp
pattern MODP_IETF_6144 = "modp/ietf/6144"

pattern MODP_IETF_8192 :: DLGrp
pattern MODP_IETF_8192 = "modp/ietf/8192"

pattern MODP_SRP_1024 :: DLGrp
pattern MODP_SRP_1024 = "modp/srp/1024"

pattern MODP_SRP_1536 :: DLGrp
pattern MODP_SRP_1536 = "modp/srp/1536"

pattern MODP_SRP_2048 :: DLGrp
pattern MODP_SRP_2048 = "modp/srp/2048"

pattern MODP_SRP_3072 :: DLGrp
pattern MODP_SRP_3072 = "modp/srp/3072"

pattern MODP_SRP_4096 :: DLGrp
pattern MODP_SRP_4096 = "modp/srp/4096"

pattern MODP_SRP_6144 :: DLGrp
pattern MODP_SRP_6144 = "modp/srp/6144"

pattern MODP_SRP_8192 :: DLGrp
pattern MODP_SRP_8192 = "modp/srp/8192"

pattern DSA_JCE_1024 :: DLGrp
pattern DSA_JCE_1024 = "dsa/jce/1024"

pattern DSA_BOTAN_2048 :: DLGrp
pattern DSA_BOTAN_2048 = "dsa/botan/2048"

pattern DSA_BOTAN_3072 :: DLGrp
pattern DSA_BOTAN_3072 = "dsa/botan/3072"

-- | Sets of allowed padding schemes for public key types.
data PkPadding = EMSA1 | EMSA4 | EMSA3

hashPadToCBytes :: HashType -> PkPadding -> CBytes
hashPadToCBytes hty pad =
  let hty' = hashTypeToCBytes hty
      pad' = pkPaddingToCBytes pad
   in hty' `append` "(" `append` pad' `append` ")"

pkPaddingToCBytes :: PkPadding -> CBytes
pkPaddingToCBytes = \case
  EMSA1 -> "EMSA1"
  EMSA4 -> "EMSA4"
  EMSA3 -> "EMSA3"

type PaddingSchemes = [CBytes]

pattern DSAPad :: PaddingSchemes
pattern DSAPad = ["EMSA1"]

pattern ECDSAPad :: PaddingSchemes
pattern ECDSAPad = ["EMSA1"]

pattern ECGDSAPad :: PaddingSchemes
pattern ECGDSAPad = ["EMSA1"]

pattern ECKCDSAPad :: PaddingSchemes
pattern ECKCDSAPad = ["EMSA1"]

pattern GOST_34_10Pad :: PaddingSchemes
pattern GOST_34_10Pad = ["EMSA1"]

pattern GOST_34_10_2012_256Pad :: PaddingSchemes
pattern GOST_34_10_2012_256Pad = ["EMSA1"]

pattern GOST_34_10_2012_512Pad :: PaddingSchemes
pattern GOST_34_10_2012_512Pad = ["EMSA1"]

pattern RSAPad :: PaddingSchemes
pattern RSAPad = ["EMSA4", "EMSA3"]

---------------------------
-- Private Key Functions --
---------------------------

maxKeySize :: Int
maxKeySize = 16

-- | A newtype wrapper.
newtype PrivKey = PrivKey BotanStruct

-- | Creating a new private key requires two things: a source of random numbers and some algorithm specific arguments that define the security level of the resulting key.
newPrivKey ::
  -- | Algorithm name and some algorithm specific arguments.
  PrivKeyType ->
  RNG ->
  IO PrivKey
newPrivKey (PrivKeyType privKeyType) rng = do
  withRNG rng $ \rng' ->
    let (algo, args) = h privKeyType
     in withCBytesUnsafe algo $ \algo' ->
          withCBytesUnsafe args $ \args' ->
            PrivKey <$> newBotanStruct (\privKey -> botan_privkey_create privKey algo' args' rng') botan_privkey_destroy
  where
    h :: KeyType -> (CBytes, CBytes)
    h keyType' = case keyType' of
      Curve25519 -> ("Curve25519", "")
      RSA bits -> ("RSA", cast' bits)
      McEliece n t -> ("McEliece", cast' n `append` "," `append` cast' t)
      XMSS xmss -> ("XMSS", xmss)
      Ed25519 -> ("Ed25519", "")
      ECC ecc grp -> (eccToCBytes ecc, grp)
      DL dl grp -> (dlToCBytes dl, grp)
    cast' :: Word32 -> CBytes
    cast' = buildCBytes . B.int

-- | Load a private key. If the key is encrypted, password will be used to attempt decryption.
loadPrivKey ::
  RNG ->
  V.Bytes ->
  -- | Password.
  CBytes ->
  IO PrivKey
loadPrivKey rng buf passwd = do
  withRNG rng $ \rng' ->
    withPrimVectorUnsafe buf $ \buf' off len ->
      withCBytesUnsafe passwd $ \passwd' ->
        PrivKey <$> newBotanStruct (\privKey -> hs_botan_privkey_load privKey rng' buf' off len passwd') botan_privkey_destroy

data KeyExportFMT = DER | PEM

keyExportFMTToWord32 :: KeyExportFMT -> Word32
keyExportFMTToWord32 = \case
  DER -> 0
  PEM -> 1

-- | Export a private key.
exportPrivKey :: PrivKey -> KeyExportFMT -> IO V.Bytes
exportPrivKey (PrivKey privKey) fmt = do
  withBotanStruct privKey $ \privKey' -> do
    (a, _) <- allocPrimVectorUnsafe maxKeySize $ \buf ->
      allocPrimUnsafe @CSize $ \size ->
        throwBotanIfMinus_ (botan_privkey_export privKey' buf size (keyExportFMTToWord32 fmt))
    return a

-- | Export a public key from a given private key.
privToPub :: PrivKey -> IO PubKey
privToPub (PrivKey priv) = do
  withBotanStruct priv $ \priv' ->
    PubKey <$> newBotanStruct (`botan_privkey_export_pubkey` priv') botan_privkey_destroy

-- | Read an algorithm specific field from the private key object.
readPrivKey :: PrivKey -> CBytes -> MPI
readPrivKey (PrivKey privKey) field = unsafeNewMPI $ \mpi ->
  withBotanStruct privKey $ \privKey' ->
    withCBytesUnsafe field $ \field' ->
      botan_privkey_get_field mpi privKey' field'

-- | A newtype wrapper.
newtype PubKey = PubKey BotanStruct

-- | Load a publickey.
loadPubKey :: V.Bytes -> IO PubKey
loadPubKey buf = do
  withPrimVectorUnsafe buf $ \buf' off len ->
    PubKey <$> newBotanStruct (\pubKey -> hs_botan_pubkey_load pubKey buf' off len) botan_pubkey_destroy

-- | Export a public key.
exportPubKey :: PubKey -> KeyExportFMT -> IO V.Bytes
exportPubKey (PubKey pubKey) fmt = do
  withBotanStruct pubKey $ \pubKey' -> do
    (a, _) <- allocPrimVectorUnsafe maxKeySize $ \buf ->
      allocPrimUnsafe @CSize $ \size ->
        throwBotanIfMinus_ (botan_privkey_export pubKey' buf size (keyExportFMTToWord32 fmt))
    return a

-- | Get the algorithm name of a public key.
algoName :: PubKey -> IO V.Bytes
algoName (PubKey pubKey) = do
  withBotanStruct pubKey $ \pubKey' -> do
    (a, _) <- allocPrimVectorUnsafe 256 $ \buf ->
      allocPrimUnsafe @CSize $ \size ->
        throwBotanIfMinus_ (botan_pubkey_algo_name pubKey' buf size)
    return a

-- | Estimate the strength of a public key.
estStr :: PubKey -> IO Int
estStr (PubKey pubKey) = do
  withBotanStruct pubKey $ \pubKey' -> do
    (a, _) <- allocPrimUnsafe @CSize $ \est ->
      throwBotanIfMinus_ (botan_pubkey_estimated_strength pubKey' est)
    return (fromIntegral a)

maxFingerPrintSize :: Int
maxFingerPrintSize = 4

-- | Finger print using a given publickey.
fingerPrint :: PubKey -> CBytes -> IO V.Bytes
fingerPrint (PubKey pubKey) hash'' = do
  withBotanStruct pubKey $ \pubKey' ->
    withCBytesUnsafe hash'' $ \hash' -> do
      (a, _) <- allocPrimVectorUnsafe maxFingerPrintSize $ \buf ->
        allocPrimUnsafe @CSize $ \size ->
          throwBotanIfMinus_ (botan_pubkey_fingerprint pubKey' hash' buf size)
      return a

-- | Read an algorithm specific field from the public key object.
readPubKey :: PubKey -> CBytes -> MPI
readPubKey (PubKey pubKey) field = unsafeNewMPI $ \mpi ->
  withBotanStruct pubKey $ \pubKey' ->
    withCBytesUnsafe field $ \field' ->
      botan_pubkey_get_field mpi pubKey' field'

----------------------------
-- RSA specific functions --
----------------------------

data RSAPrivArg = RSAPrivP | RSAPrivQ | RSAPrivD | RSAPrivN | RSAPrivE

getRSAPriv :: PrivKey -> RSAPrivArg -> MPI
getRSAPriv (PrivKey privKey) arg = unsafeNewMPI $ \mpi ->
  withBotanStruct privKey $ \privKey' ->
    ( case arg of
        RSAPrivP -> botan_privkey_rsa_get_p
        RSAPrivQ -> botan_privkey_rsa_get_q
        RSAPrivD -> botan_privkey_rsa_get_d
        RSAPrivN -> botan_privkey_rsa_get_n
        RSAPrivE -> botan_privkey_rsa_get_e
    )
      mpi
      privKey'

data RSAPubArg = RSAPubE | RSAPubN

getRSAPub :: PubKey -> RSAPubArg -> MPI
getRSAPub (PubKey pubKey) arg = unsafeNewMPI $ \mpi ->
  withBotanStruct pubKey $ \pubKey' ->
    ( case arg of
        RSAPubN -> botan_pubkey_rsa_get_n
        RSAPubE -> botan_pubkey_rsa_get_e
    )
      mpi
      pubKey'

-- | Initialize a private RSA key using arguments p, q, and e.
newRSAPriv :: MPI -> MPI -> MPI -> PrivKey
newRSAPriv p q e = do
  unsafeWithMPI p $ \p' ->
    withMPI q $ \q' ->
      withMPI e $ \e' ->
        PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_rsa privKey p' q' e') botan_privkey_destroy

-- | Initialize a public RSA key using arguments n and e.
newRSAPub :: MPI -> MPI -> PubKey
newRSAPub n e = do
  unsafeWithMPI n $ \n' ->
    withMPI e $ \e' ->
      PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_rsa pubKey n' e') botan_pubkey_destroy

----------------------------
-- DSA specific functions --
----------------------------

newDSAPriv :: MPI -> MPI -> MPI -> MPI -> PrivKey
newDSAPriv p q g x = do
  unsafeWithMPI p $ \p' ->
    withMPI q $ \q' ->
      withMPI g $ \g' ->
        withMPI x $ \x' ->
          PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_dsa privKey p' q' g' x') botan_privkey_destroy

newDSAPub :: MPI -> MPI -> MPI -> MPI -> PubKey
newDSAPub p q g y = do
  unsafeWithMPI p $ \p' ->
    withMPI q $ \q' ->
      withMPI g $ \g' ->
        withMPI y $ \y' ->
          PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_dsa pubKey p' q' g' y') botan_pubkey_destroy

--------------------------------
-- ElGamal specific functions --
--------------------------------

newElGamalPriv :: MPI -> MPI -> MPI -> PrivKey
newElGamalPriv p g x = do
  unsafeWithMPI p $ \p' ->
    withMPI g $ \g' ->
      withMPI x $ \x' ->
        PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_elgamal privKey p' g' x') botan_privkey_destroy

newElGamalPub :: MPI -> MPI -> MPI -> PubKey
newElGamalPub p g y = do
  unsafeWithMPI p $ \p' ->
    withMPI g $ \g' ->
      withMPI y $ \y' ->
        PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_elgamal pubKey p' g' y') botan_pubkey_destroy

---------------------------------------
-- Diffie-Hellman specific functions --
---------------------------------------

newDHPriv :: MPI -> MPI -> MPI -> PrivKey
newDHPriv p g x = do
  unsafeWithMPI p $ \p' -> withMPI g $ \g' -> withMPI x $ \x' ->
    PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_dh privKey p' g' x') botan_privkey_destroy

newDHPub :: MPI -> MPI -> MPI -> PubKey
newDHPub p g y = do
  unsafeWithMPI p $ \p' ->
    withMPI g $ \g' ->
      withMPI y $ \y' ->
        PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_dh pubKey p' g' y') botan_pubkey_destroy

----------------------------------------
-- Public Key Encryption / Decryption --
----------------------------------------

newtype PKEncryption = PKEncryption BotanStruct

newPKEncryption :: PubKey -> PkPadding -> IO PKEncryption
newPKEncryption (PubKey pubKey) padding = do
  let padding' = pkPaddingToCBytes padding
   in withCBytesUnsafe padding' $ \padding'' ->
        withBotanStruct pubKey $ \pubKey' ->
          PKEncryption <$> newBotanStruct (\op -> botan_pk_op_encrypt_create op pubKey' padding'' 0) botan_pk_op_encrypt_destroy -- Flags should be 0 in this version.

pkEncryptLen :: PKEncryption -> Int -> IO Int
pkEncryptLen (PKEncryption op) len = do
  withBotanStruct op $ \op' -> do
    (a, _) <- allocPrimUnsafe $ \ret -> throwBotanIfMinus_ (botan_pk_op_encrypt_output_length op' len ret)
    return a

pkEncrypt :: PKEncryption -> RNG -> V.Bytes -> IO V.Bytes
pkEncrypt enop@(PKEncryption op) rng ptext = do
  withBotanStruct op $ \op' ->
    withRNG rng $ \rng' ->
      withPrimVectorUnsafe ptext $ \ptext' ptextOff ptextLen -> do
        len <- pkEncryptLen enop ptextLen
        (a, _) <- allocPrimVectorUnsafe len $ \out -> do
          (a', _) <- allocPrimUnsafe @Int $ \outLen ->
            throwBotanIfMinus_ (hs_botan_pk_op_encrypt op' rng' out outLen ptext' ptextOff ptextLen)
          pure a'
        return a

newtype PKDecryption = PKDecryption BotanStruct

newPKDecryption :: PrivKey -> CBytes -> IO PKDecryption
newPKDecryption (PrivKey privKey) padding = do
  withCBytesUnsafe padding $ \padding' ->
    withBotanStruct privKey $ \privKey' ->
      PKDecryption <$> newBotanStruct (\op -> botan_pk_op_decrypt_create op privKey' padding' 0) botan_pk_op_decrypt_destroy -- Flags should be 0 in this version.

pkDecryptLen :: PKDecryption -> Int -> IO Int
pkDecryptLen (PKDecryption op) len = do
  withBotanStruct op $ \op' -> do
    (a, _) <- allocPrimUnsafe $ \ret -> throwBotanIfMinus_ (botan_pk_op_decrypt_output_length op' len ret)
    return a

pkDecrypt :: PKDecryption -> V.Bytes -> IO V.Bytes
pkDecrypt enop@(PKDecryption op) ciphertext = do
  withBotanStruct op $ \op' ->
    withPrimVectorUnsafe ciphertext $ \ciphertext' ciphertextOff ciphertextLen -> do
      len <- pkDecryptLen enop ciphertextLen
      (a, _) <- allocPrimVectorUnsafe len $ \out -> do
        (a', _) <- allocPrimUnsafe @Int $ \outLen ->
          throwBotanIfMinus_ (hs_botan_pk_op_decrypt op' out outLen ciphertext' ciphertextOff ciphertextLen)
        pure a'
      return a

--------------------------
-- Signature Generation --
--------------------------

newtype SignGeneration = SignGeneration BotanStruct

data KeyOPFMT = DER_SEQUENCE | IEEE_1363

keyOPFMTToWord32 :: KeyOPFMT -> Word32
keyOPFMTToWord32 = \case
  DER_SEQUENCE -> 0
  IEEE_1363 -> 1

newPKSignGen :: PrivKey -> HashType -> PkPadding -> KeyOPFMT -> IO SignGeneration
newPKSignGen (PrivKey privKey) hobj pad fmt = do
  withBotanStruct privKey $ \privKey' ->
    withCBytesUnsafe (hashPadToCBytes hobj pad) $ \arg ->
      SignGeneration <$> newBotanStruct (\ret -> botan_pk_op_sign_create ret privKey' arg (keyOPFMTToWord32 fmt)) botan_pk_op_sign_destroy

pkSignLenGen :: SignGeneration -> IO Int
pkSignLenGen (SignGeneration op) = do
  (a, _) <- allocPrimUnsafe $ \len ->
    withBotanStruct op $ \op' ->
      throwBotanIfMinus_ $ botan_pk_op_sign_output_length op' len
  return a

updatePKSignGen :: SignGeneration -> V.Bytes -> IO ()
updatePKSignGen (SignGeneration op) msg = do
  withBotanStruct op $ \op' ->
    withPrimVectorUnsafe msg $ \msg' off len ->
      throwBotanIfMinus_ $ hs_botan_pk_op_sign_update op' msg' off len

finPKSignGen :: SignGeneration -> RNG -> IO V.Bytes
finPKSignGen gen@(SignGeneration op) rng = do
  withBotanStruct op $ \op' ->
    withRNG rng $ \rng' -> do
      len <- pkSignLenGen gen
      (a, _) <- allocPrimVectorUnsafe len $ \ret -> do
        (a', _) <- allocPrimUnsafe @Int $ \len' ->
          throwBotanIfMinus_ $ botan_pk_op_sign_finish op' rng' ret len'
        pure a'
      return a

----------------------------
-- Signature Verification --
----------------------------

newtype SignVerification = SignVerification BotanStruct

newPKSignVf :: PubKey -> HashType -> PkPadding -> KeyOPFMT -> IO SignVerification
newPKSignVf (PubKey pubKey) hobj pad fmt = do
  withBotanStruct pubKey $ \pubKey' ->
    withCBytesUnsafe (hashPadToCBytes hobj pad) $ \arg ->
      SignVerification <$> newBotanStruct (\ret -> botan_pk_op_verify_create ret pubKey' arg (keyOPFMTToWord32 fmt)) botan_pk_op_verify_destroy

updatePKSignVf :: SignVerification -> V.Bytes -> IO ()
updatePKSignVf (SignVerification op) msg = do
  withBotanStruct op $ \op' ->
    withPrimVectorUnsafe msg $ \msg' off len ->
      throwBotanIfMinus_ $ hs_botan_pk_op_verify_update op' msg' off len

finPKSignVf :: SignVerification -> V.Bytes -> IO ()
finPKSignVf (SignVerification op) msg = do
  withBotanStruct op $ \op' ->
    withPrimVectorUnsafe msg $ \msg' off len ->
      throwBotanIfMinus_ $ hs_botan_pk_op_verify_finish op' msg' off len

--  BOTAN_FFI_SUCCESS = 0,
--  BOTAN_FFI_INVALID_VERIFIER = 1

-------------------
-- Key Agreement --
-------------------

newtype PKAgreement = PKAgreement BotanStruct

newPKAgree :: PrivKey -> CBytes -> KeyOPFMT -> IO PKAgreement
newPKAgree (PrivKey privKey) kdf fmt = do
  withBotanStruct privKey $ \privKey' ->
    withCBytesUnsafe kdf $ \kdf' ->
      PKAgreement <$> newBotanStruct (\ret -> botan_pk_op_key_agreement_create ret privKey' kdf' (keyOPFMTToWord32 fmt)) botan_pk_op_key_agreement_destroy

maxAgreeSize :: Int
maxAgreeSize = 16

exportPKAgree :: PrivKey -> IO V.Bytes
exportPKAgree (PrivKey privKey) = do
  withBotanStruct privKey $ \privKey' -> do
    (a, _) <- allocPrimVectorUnsafe maxAgreeSize $ \ret -> do
      (a', _) <- allocPrimUnsafe @Int $ \len ->
        throwBotanIfMinus_ $ botan_pk_op_key_agreement_export_public privKey' ret len
      pure a'
    return a

pkAgree :: PKAgreement -> V.Bytes -> V.Bytes -> IO V.Bytes
pkAgree (PKAgreement op) others salt = do
  withBotanStruct op $ \op' ->
    withPrimVectorUnsafe others $ \others' others_off others_len ->
      withPrimVectorUnsafe salt $ \salt' salt_off salt_len -> do
        (a, _) <- allocPrimVectorUnsafe maxAgreeSize $ \ret -> do
          (a', _) <- allocPrimUnsafe @Int $ \len ->
            throwBotanIfMinus_ $ hs_botan_pk_op_key_agreement op' ret len others' others_off others_len salt' salt_off salt_len
          pure a'
        return a
