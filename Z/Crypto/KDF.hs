{-|
Module      : Z.Crypto.KDF
Description : Key Derivation Functions
Copyright   : Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

KDF(Key Derivation Function) and PBKDF(Password Based Key Derivation Function).

-}
module Z.Crypto.KDF (
  -- * KDF
    KDFType(..)
  , BlockCipherType (..)
  , HashType(..)
  , kdf
  , kdf'
  -- * PBKDF
  , PBKDFType(..)
  , pbkdf
  , pbkdfTimed
  -- * Internal helps
  , kDFTypeToCBytes
  , pBKDFTypeToParam
  ) where

import Z.Crypto.Cipher (BlockCipherType (..), blockCipherTypeToCBytes)
import Z.Crypto.Hash
import Z.Botan.FFI
import Z.Data.CBytes (CBytes, withCBytesUnsafe, withCBytes)
import qualified Z.Data.CBytes as CB
import qualified Z.Data.Vector as V
import Z.Foreign
import Z.Botan.Exception

-----------------------------
-- Key Derivation Function --
-----------------------------

-- | Key derivation functions are used to turn some amount of shared secret material into uniform random keys suitable for use with symmetric algorithms. An example of an input which is useful for a KDF is a shared secret created using Diffie-Hellman key agreement.
data KDFType
    = HKDF HashType
    | HKDF_Extract HashType
    | HKDF_Expand HashType
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
    -- ^
    | TLS_12_PRF HashType
    | SP800_108_Counter HashType
    | SP800_108_Counter' BlockCipherType
    | SP800_108_Feedback HashType
    | SP800_108_Feedback' BlockCipherType
    | SP800_108_Pipeline HashType
    | SP800_108_Pipeline' BlockCipherType
    | SP800_56AHash HashType
    -- ^ NIST SP 800-56A KDF using hash function
    | SP800_56AHMAC HashType
    -- ^ NIST SP 800-56A KDF using HMAC
    | SP800_56C HashType

kDFTypeToCBytes :: KDFType -> CBytes
kDFTypeToCBytes (HKDF ht        ) = CB.concat [ "HKDF(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (HKDF_Extract ht) = CB.concat [ "HKDF-Extract(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (HKDF_Expand ht ) = CB.concat [ "HKDF-Expand(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (KDF2 ht        ) = CB.concat [ "KDF2(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (KDF1_18033 ht  ) = CB.concat [ "KDF1-18033(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (KDF1 ht        ) = CB.concat [ "KDF1(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (TLS_PRF        ) = "TLS-PRF"
kDFTypeToCBytes (TLS_12_PRF ht  ) = CB.concat [ "TLS-12-PRF(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (SP800_108_Counter ht  ) = CB.concat [ "SP800-108-Counter(HMAC(" , hashTypeToCBytes ht, "))"]
kDFTypeToCBytes (SP800_108_Counter' ct ) = CB.concat [ "SP800-108-Counter(CMAC(" , blockCipherTypeToCBytes ct, "))"]
kDFTypeToCBytes (SP800_108_Feedback ht ) = CB.concat [ "SP800-108-Feedback(HMAC(" , hashTypeToCBytes ht, "))"]
kDFTypeToCBytes (SP800_108_Feedback' ct) = CB.concat [ "SP800-108-Feedback(CMAC(" , blockCipherTypeToCBytes ct, "))"]
kDFTypeToCBytes (SP800_108_Pipeline ht ) = CB.concat [ "SP800-108-Pipeline(HMAC(" , hashTypeToCBytes ht, "))"]
kDFTypeToCBytes (SP800_108_Pipeline' ct) = CB.concat [ "SP800-108-Pipeline(CMAC(" , blockCipherTypeToCBytes ct, "))"]
kDFTypeToCBytes (SP800_56AHash ht      ) = CB.concat [ "SP800-56A(" , hashTypeToCBytes ht, ")"]
kDFTypeToCBytes (SP800_56AHMAC ht      ) = CB.concat [ "SP800-56A(HMAC(" , hashTypeToCBytes ht, "))"]
kDFTypeToCBytes (SP800_56C ht          ) = CB.concat [ "SP800-56C(" , hashTypeToCBytes ht, ")"]

-- | Derive a key using the given KDF algorithm.
kdf
  :: KDFType    -- ^ the name of the given PBKDF algorithm
  -> Int        -- ^ length of output key
  -> V.Bytes    -- ^ secret
  -> V.Bytes    -- ^ salt
  -> V.Bytes    -- ^ label
  -> IO V.Bytes
kdf algo siz secret salt label =
    withCBytesUnsafe (kDFTypeToCBytes algo) $ \ algoBA ->
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
kdf'
  :: KDFType    -- ^ the name of the given PBKDF algorithm
  -> Int        -- ^ length of output key
  -> V.Bytes    -- ^ secret
  -> IO V.Bytes
kdf' algo siz secret = kdf algo siz secret mempty mempty

--------------------------------------------
-- Password-Based Key Derivation Function --
--------------------------------------------

-- | Often one needs to convert a human readable password into a cryptographic key. It is useful to slow down the computation of these computations in order to reduce the speed of brute force search, thus they are parameterized in some way which allows their required computation to be tuned.
data PBKDFType
    = PBKDF2 HashType Int   -- ^ iterations
    -- ^ PBKDF2 is the “standard” password derivation scheme,
    -- widely implemented in many different libraries. It uses HMAC internally.
    | PBKDF2' BlockCipherType Int   -- ^ iterations
    -- ^ PBKDF2 is the “standard” password derivation scheme,
    -- widely implemented in many different libraries. It uses HMAC internally.
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

pBKDFTypeToParam :: PBKDFType -> (CBytes, Int, Int, Int)
pBKDFTypeToParam (PBKDF2 ht i     ) = (CB.concat [ "PBKDF2(HMAC(" , hashTypeToCBytes ht, "))"], i, 0, 0)
pBKDFTypeToParam (PBKDF2' ct i    ) = (CB.concat [ "PBKDF2(CMAC(" , blockCipherTypeToCBytes ct, "))"], i, 0, 0)
pBKDFTypeToParam (Scrypt n r p    ) = ("Scrypt", n, r, p)
pBKDFTypeToParam (Argon2d i m p   ) = ("Argon2d", i, m, p)
pBKDFTypeToParam (Argon2i i m p   ) = ("Argon2i", i, m, p)
pBKDFTypeToParam (Argon2id i m p  ) = ("Argon2id", i, m, p)
pBKDFTypeToParam (Bcrypt i        ) = ("Bcrypt-PBKDF", i, 0, 0)
pBKDFTypeToParam (OpenPGP_S2K ht i) = (CB.concat [ "OpenPGP-S2K(" , hashTypeToCBytes ht, ")"], i, 0, 0)

-- | Derive a key from a passphrase for a number of iterations using the given PBKDF algorithm and params.
pbkdf :: PBKDFType  -- ^ PBKDF algorithm type
      -> Int        -- ^ length of output key
      -> V.Bytes    -- ^ passphrase
      -> V.Bytes    -- ^ salt
      -> IO V.Bytes
pbkdf typ siz pwd salt = do
    withCBytesUnsafe algo $ \ algoBA ->
        withPrimVectorUnsafe pwd $ \ pwdBA ppOff ppLen ->
            withPrimVectorUnsafe salt $ \ saltBA saltOff saltLen -> do
                fst <$> allocPrimVectorUnsafe siz (\ buf -> do
                    clearMBA buf siz
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash algoBA
                            i1 i2 i3
                            buf (fromIntegral siz)
                            pwdBA ppOff ppLen
                            saltBA saltOff saltLen)
  where
    (algo, i1, i2, i3) = pBKDFTypeToParam typ

-- | Derive a key from a passphrase using the given PBKDF algorithm, the iteration params are ignored and PBKDF is run until given milliseconds have passed.
pbkdfTimed :: PBKDFType  -- ^ the name of the given PBKDF algorithm
           -> Int        -- ^ run until milliseconds have passwd
           -> Int        -- ^ length of output key
           -> V.Bytes    -- ^ passphrase
           -> V.Bytes    -- ^ salt
           -> IO V.Bytes
pbkdfTimed typ msec siz pwd s =
    -- we want run it in new OS thread without stop GC from running
    -- if the expected time is too long(>0.1s)
    if msec > 100
    then withCBytes algo $ \algo' ->
        withPrimVectorSafe pwd $ \pwd' ppLen ->
            withPrimVectorSafe s $ \s' sLen ->
                fst <$> allocPrimVectorSafe siz (\ buf -> do
                    clearPtr buf siz
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash_timed_safe
                            algo' msec buf (fromIntegral siz)
                            pwd' 0 ppLen
                            s' 0 sLen)
    else withCBytesUnsafe algo $ \algo' ->
        withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
            withPrimVectorUnsafe s $ \s' sOff sLen ->
                fst <$> allocPrimVectorUnsafe siz (\ buf -> do
                    clearMBA buf siz
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash_timed
                            algo' msec buf (fromIntegral siz)
                            pwd' ppOff ppLen
                            s' sOff sLen)
  where
    (algo, _, _, _) = pBKDFTypeToParam typ
