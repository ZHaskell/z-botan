module Z.Crypto.KDF where

import Data.Word (Word8)
import Z.Crypto.Hash
import Z.Botan.FFI (hs_botan_kdf, hs_botan_pwdhash, hs_botan_pwdhash_timed)
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.CBytes as CB
import qualified Z.Data.Vector as V
import Z.Foreign (allocPrimVectorUnsafe, withPrimVectorUnsafe, allocPrimArrayUnsafe)
import Z.Botan.Exception ( throwBotanIfMinus_ )

-----------------------------
-- Key Derivation Function --
-----------------------------

-- | Key derivation functions are used to turn some amount of shared secret material into uniform random keys suitable for use with symmetric algorithms. An example of an input which is useful for a KDF is a shared secret created using Diffie-Hellman key agreement.
data KDFType
    = HKDF HashType
    | HKDF_Extract HashType
    | HKDF_Expand HashType
    | KDF2 HashType
    -- ^ PBKDF2 is the “standard” password derivation scheme,
    -- widely implemented in many different libraries. It uses HMAC internally.
    | KDF1_18033 HashType
    | KDF1 HashType
    | TLS_PRF
    | TLS_12_PRF HashType
    | SP800_108
    | SP800_56A
    | SP800_56C

kdfTypeToCBytes :: KDFType -> CBytes
kdfTypeToCBytes (HKDF ht        ) = CB.concat [ "HKDF(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (HKDF_Extract ht) = CB.concat [ "HKDF-Extract(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (HKDF_Expand ht ) = CB.concat [ "HKDF-Expand(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (KDF2 ht      ) = CB.concat [ "PBKDF2(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (KDF1_18033 ht  ) = CB.concat [ "KDF1-18033(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (KDF1 ht        ) = CB.concat [ "KDF1(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (TLS_PRF        ) = "TLS_PRF"
kdfTypeToCBytes (TLS_12_PRF ht  ) = CB.concat [ "TLS-12-PRF(" , hashTypeToCBytes ht, ")"]
kdfTypeToCBytes (SP800_108      ) = "SP800-108"
kdfTypeToCBytes (SP800_56A      ) = "SP800-56A"
kdfTypeToCBytes (SP800_56C      ) = "SP800-56C"

-- | Derive a key using the given KDF algorithm.
kdf
  :: KDFType    -- ^ the name of the given PBKDF algorithm
  -> Int        -- ^ length of output key
  -> V.Bytes    -- ^ secret
  -> V.Bytes    -- ^ salt
  -> V.Bytes    -- ^ label
  -> IO V.Bytes
kdf algo siz secret salt label =
    withCBytesUnsafe (kdfTypeToCBytes algo) $ \ algoBA ->
        withPrimVectorUnsafe secret $ \ secretBA secretOff secretLen ->
            withPrimVectorUnsafe salt $ \ saltBA saltOff saltLen ->
                withPrimVectorUnsafe label $ \ labelBA labelOff labelLen ->
                    fst <$> allocPrimVectorUnsafe siz (\ buf ->
                        throwBotanIfMinus_ $
                            hs_botan_kdf algoBA buf (fromIntegral siz)
                                secretBA secretOff secretLen
                                saltBA saltOff saltLen
                                labelBA labelOff labelLen)

--------------------------------------------
-- Password-Based Key Derivation Function --
--------------------------------------------

-- | Often one needs to convert a human readable password into a cryptographic key. It is useful to slow down the computation of these computations in order to reduce the speed of brute force search, thus they are parameterized in some way which allows their required computation to be tuned.
data PBKDFType
    = PBKDF2 HashType Int   -- ^ iterations
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

pBKDFType2Param :: PBKDFType -> (CBytes, Int, Int, Int)
pBKDFType2Param (PBKDF2 ht i     ) = (CB.concat [ "PBKDF2(" , hashTypeToCBytes ht, ")"], i, 0, 0)
pBKDFType2Param (Scrypt n r p    ) = ("Scrypt", n, r, p)
pBKDFType2Param (Argon2d i m p   ) = ("Argon2d", i, m, p)
pBKDFType2Param (Argon2i i m p   ) = ("Argon2i", i, m, p)
pBKDFType2Param (Argon2id i m p  ) = ("Argon2id", i, m, p)
pBKDFType2Param (Bcrypt i        ) = ("Bcrypt-PBKDF", i, 0, 0)
pBKDFType2Param (OpenPGP_S2K ht i) = (CB.concat [ "OpenPGP-S2K(" , hashTypeToCBytes ht, ")"], i, 0, 0)

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
                fst <$> allocPrimVectorUnsafe siz (\ buf ->
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash algoBA
                            i1 i2 i3
                            buf (fromIntegral siz)
                            pwdBA ppOff ppLen
                            saltBA saltOff saltLen)
  where
    (algo, i1, i2, i3) = pBKDFType2Param typ

-- | Derive a key from a passphrase using the given PBKDF algorithm, the param is ignored and PBKDF is run until given milliseconds have passed.
pbkdfTimed :: PBKDFType  -- ^ the name of the given PBKDF algorithm
           -> Int        -- ^ run until milliseconds have passwd
           -> Int        -- ^ length of output key
           -> V.Bytes    -- ^ passphrase
           -> V.Bytes    -- ^ salt
           -> IO V.Bytes
pbkdfTimed typ msec siz pwd s =
    withCBytesUnsafe algo $ \algo' ->
        withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
            withPrimVectorUnsafe s $ \s' sOff sLen ->
                fst <$> allocPrimVectorUnsafe siz (\ buf ->
                    throwBotanIfMinus_ $
                        hs_botan_pwdhash_timed algo' msec buf (fromIntegral siz)
                            pwd' ppOff ppLen
                            s' sOff sLen)
  where
    (algo, _, _, _) = pBKDFType2Param typ
