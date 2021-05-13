{-|
Module      : Z.Crypto.KDF
Description : Key Derivation Functions
Copyright   : Dong Han, 2021
              AnJie Dong, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

KDF(Key Derivation Function) and PBKDF(Password Based Key Derivation Function).

-}
module Z.Crypto.KDF (
  -- * KDF
    KDFType(..)
  , HashType(..)
  , MACType(..)
  , kdf
  , kdf'
  -- * PBKDF
  , PBKDFType(..)
  , pbkdf
  , pbkdfTimed
  -- * Internal helps
  , kdfTypeToCBytes
  , pbkdfTypeToParam
  ) where

import           GHC.Generics
import           Z.Botan.Exception
import           Z.Botan.FFI
import           Z.Crypto.Hash     (HashType (..), hashTypeToCBytes)
import           Z.Crypto.MAC      (MACType (..), macTypeToCBytes)
import           Z.Data.CBytes     (CBytes, withCBytes, withCBytesUnsafe)
import qualified Z.Data.CBytes     as CB
import           Z.Data.JSON       (JSON)
import qualified Z.Data.Text       as T
import qualified Z.Data.Vector     as V
import           Z.Foreign

-----------------------------
-- Key Derivation Function --
-----------------------------

-- | Key derivation functions are used to turn some amount of shared secret material into uniform random keys
-- suitable for use with symmetric algorithms. An example of an input which is useful for a KDF is a shared
-- secret created using Diffie-Hellman key agreement.
data KDFType
    = HKDF MACType
    | HKDF_Extract MACType
    | HKDF_Expand MACType
    -- ^ Defined in RFC 5869, HKDF uses HMAC to process inputs.
    -- Also available are variants HKDF-Extract and HKDF-Expand.
    -- HKDF is the combined Extract+Expand operation.
    -- Use the combined HKDF unless you need compatibility with some other system.
    | KDF2 HashType
    -- ^ KDF2 comes from IEEE 1363. It uses a hash function.
    | KDF1_18033 HashType
    -- ^ KDF1 from ISO 18033-2. Very similar to (but incompatible with) KDF2.
    | KDF1 HashType
    -- ^ KDF1 from IEEE 1363. It can only produce an output at most the length of the hash function used.
    | TLS_PRF
    -- ^ A KDF from ANSI X9.42. Sometimes used for Diffie-Hellman.
    | TLS_12_PRF MACType
    | SP800_108_Counter MACType
    -- ^ KDFs from NIST SP 800-108. Variants include “SP800-108-Counter”, “SP800-108-Feedback” and “SP800-108-Pipeline”.
    | SP800_108_Feedback MACType
    | SP800_108_Pipeline MACType
    | SP800_56AHash HashType
    -- ^ NIST SP 800-56A KDF using hash function
    | SP800_56AMAC MACType
    -- ^ NIST SP 800-56A KDF using HMAC
    | SP800_56C MACType
    -- ^ NIST SP 800-56C KDF using HMAC
  deriving (Show, Read, Eq, Ord, Generic)
  deriving anyclass (T.Print, JSON)

kdfTypeToCBytes :: KDFType -> CBytes
kdfTypeToCBytes (HKDF mt        ) = CB.concat [ "HKDF(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (HKDF_Extract mt) = CB.concat [ "HKDF-Extract(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (HKDF_Expand mt ) = CB.concat [ "HKDF-Expand(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (KDF2 ht        ) = CB.concat [ "KDF2(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (KDF1_18033 ht  ) = CB.concat [ "KDF1-18033(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (KDF1 ht        ) = CB.concat [ "KDF1(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (TLS_PRF        ) = "TLS-PRF"
kdfTypeToCBytes (TLS_12_PRF mt  ) = CB.concat [ "TLS-12-PRF(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (SP800_108_Counter mt ) = CB.concat [ "SP800-108-Counter(" ,  macTypeToCBytes mt, ")"]
kdfTypeToCBytes (SP800_108_Feedback mt) = CB.concat [ "SP800-108-Feedback(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (SP800_108_Pipeline mt) = CB.concat [ "SP800-108-Pipeline(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (SP800_56AHash ht     ) = CB.concat [ "SP800-56A(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (SP800_56AMAC mt      ) = CB.concat [ "SP800-56A(" , macTypeToCBytes mt, ")"]
kdfTypeToCBytes (SP800_56C mt         ) = CB.concat [ "SP800-56C(" , macTypeToCBytes mt, ")"]

-- | Derive a key using the given KDF algorithm.
kdf :: HasCallStack
    => KDFType    -- ^ the name of the given PBKDF algorithm
    -> Int        -- ^ length of output key
    -> V.Bytes    -- ^ secret
    -> V.Bytes    -- ^ salt
    -> V.Bytes    -- ^ label
    -> IO V.Bytes
{-# INLINABLE kdf #-}
kdf algo siz secret salt label =
    withCBytesUnsafe (kdfTypeToCBytes algo) $ \ algoBA ->
        withPrimVectorUnsafe secret $ \ secretBA secretOff secretLen ->
            withPrimVectorUnsafe salt $ \ saltBA saltOff saltLen ->
                withPrimVectorUnsafe label $ \ labelBA labelOff labelLen ->
                    fst <$> allocPrimVectorUnsafe siz (\ buf -> do
                        -- some kdf needs xor output buffer, so we clear it first
                        clearMBA buf siz
                        throwBotanIfMinus_ $
                            hs_botan_kdf algoBA buf (fromIntegral siz)
                                secretBA secretOff secretLen
                                saltBA saltOff saltLen
                                labelBA labelOff labelLen)

-- | Derive a key using the given KDF algorithm, with default empty salt and label.
kdf' :: HasCallStack
     => KDFType    -- ^ the name of the given PBKDF algorithm
     -> Int        -- ^ length of output key
     -> V.Bytes    -- ^ secret
     -> IO V.Bytes
{-# INLINABLE kdf' #-}
kdf' algo siz secret = kdf algo siz secret mempty mempty

--------------------------------------------
-- Password-Based Key Derivation Function --
--------------------------------------------

-- | Often one needs to convert a human readable password into a cryptographic key. It is useful to slow down the
-- computation of these computations in order to reduce the speed of brute force search, thus they are parameterized
-- in some way which allows their required computation to be tuned.
data PBKDFType
    = PBKDF2 MACType Int   -- ^ iterations
    -- ^ PBKDF2 is the “standard” password derivation scheme,
    -- widely implemented in many different libraries.
    | Scrypt  Int Int Int   -- ^ N, r, p
    -- ^ Scrypt is a relatively newer design which is “memory hard”,
    -- in addition to requiring large amounts of CPU power it uses a large block of memory to compute the hash.
    -- This makes brute force attacks using ASICs substantially more expensive.
    | Argon2d Int Int Int   -- ^ iterations, memory, parallelism
    -- ^ Argon2 is the winner of the PHC (Password Hashing Competition) and provides a tunable memory hard PBKDF.
    | Argon2i Int Int Int   -- ^ iterations, memory, parallelism
    | Argon2id Int Int Int  -- ^ iterations, memory, parallelism
    | Bcrypt Int            -- ^ iterations
    | OpenPGP_S2K HashType Int -- ^ iterations
    -- ^ The OpenPGP algorithm is weak and strange, and should be avoided unless implementing OpenPGP.

pbkdfTypeToParam :: PBKDFType -> (CBytes, Int, Int, Int)
pbkdfTypeToParam (PBKDF2 mt i     ) = (CB.concat [ "PBKDF2(" , macTypeToCBytes mt, ")"], i, 0, 0)
pbkdfTypeToParam (Scrypt n r p    ) = ("Scrypt", n, r, p)
pbkdfTypeToParam (Argon2d i m p   ) = ("Argon2d", i, m, p)
pbkdfTypeToParam (Argon2i i m p   ) = ("Argon2i", i, m, p)
pbkdfTypeToParam (Argon2id i m p  ) = ("Argon2id", i, m, p)
pbkdfTypeToParam (Bcrypt i        ) = ("Bcrypt-PBKDF", i, 0, 0)
pbkdfTypeToParam (OpenPGP_S2K ht i) = (CB.concat [ "OpenPGP-S2K(" , hashTypeToCBytes ht, ")"], i, 0, 0)

-- | Derive a key from a passphrase for a number of iterations using the given PBKDF algorithm and params.
pbkdf :: HasCallStack
      => PBKDFType  -- ^ PBKDF algorithm type
      -> Int        -- ^ length of output key
      -> CBytes     -- ^ passphrase
      -> V.Bytes    -- ^ salt
      -> IO V.Bytes
{-# INLINABLE pbkdf #-}
pbkdf typ siz pwd salt = do
    withCBytesUnsafe algo $ \ algoBA ->
        withCBytesUnsafe pwd $ \ pwdBA ->
            withPrimVectorUnsafe salt $ \ saltBA saltOff saltLen -> do
                fst <$> allocPrimVectorUnsafe siz (\ buf -> do
                    clearMBA buf siz
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash algoBA
                            i1 i2 i3
                            buf (fromIntegral siz)
                            pwdBA (CB.length pwd)
                            saltBA saltOff saltLen)
  where
    (algo, i1, i2, i3) = pbkdfTypeToParam typ

-- | Derive a key from a passphrase using the given PBKDF algorithm, the iteration params are
-- ignored and PBKDF is run until given milliseconds have passed.
pbkdfTimed :: HasCallStack
           => PBKDFType  -- ^ the name of the given PBKDF algorithm
           -> Int        -- ^ run until milliseconds have passwd
           -> Int        -- ^ length of output key
           -> CBytes     -- ^ passphrase
           -> V.Bytes    -- ^ salt
           -> IO V.Bytes
{-# INLINABLE pbkdfTimed #-}
pbkdfTimed typ msec siz pwd s = do
    -- we want run it in new OS thread without stop GC from running
    -- if the expected time is too long(>0.1s)
    if msec > 100
    then withCBytes algo $ \algo' ->
        withCBytes pwd $ \ pwd' ->
            withPrimVectorSafe s $ \s' sLen ->
                fst <$> allocPrimVectorSafe siz (\ buf -> do
                    clearPtr buf siz
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash_timed_safe
                            algo' msec buf (fromIntegral siz)
                            pwd' (CB.length pwd) s' 0 sLen)
    else withCBytesUnsafe algo $ \algo' ->
        withCBytesUnsafe pwd $ \ pwd' ->
            withPrimVectorUnsafe s $ \s' sOff sLen ->
                fst <$> allocPrimVectorUnsafe siz (\ buf -> do
                    clearMBA buf siz
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash_timed
                            algo' msec buf (fromIntegral siz)
                            pwd' (CB.length pwd) s' sOff sLen)
  where
    (algo, _, _, _) = pbkdfTypeToParam typ
