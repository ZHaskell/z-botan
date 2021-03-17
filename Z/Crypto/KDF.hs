module Z.Crypto.KDF where

import Data.Word (Word8)
import Z.Botan.FFI (hs_botan_kdf, hs_botan_pwdhash, hs_botan_pwdhash_timed)
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign (allocPrimVectorUnsafe, withPrimVectorUnsafe, allocPrimArrayUnsafe)
import Z.Botan.Exception ( throwBotanIfMinus_ )

-----------------------------
-- Key Derivation Function --
-----------------------------

-- | Derive a key using the given KDF algorithm.
kdf
  :: CBytes
  -- ^ the name of the given PBKDF algorithm
  -> Int
  -- ^ length of output key
  -> V.Bytes
  -- ^ secret
  -> V.Bytes
  -- ^ salt
  -> IO V.Bytes
kdf algo siz secret salt = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe secret $ \secret' secretOff secretLen ->
      withPrimVectorUnsafe salt $ \salt' saltOff saltLen -> do
        (b, _) <- allocPrimVectorUnsafe @Word8 siz $ \buf ->
          throwBotanIfMinus_ (hs_botan_kdf algo' buf (fromIntegral siz) secret' secretOff secretLen salt' saltOff saltLen)
        return b

--------------------------------------------
-- Password-Based Key Derivation Function --
--------------------------------------------

-- | Derive a key from a passphrase for a number of iterations using the given PBKDF algorithm.
pwdHash
  :: CBytes
  -- ^ the name of the given PBKDF algorithm
  -> Int
  -- ^ the first argument of algorithm
  -> Int
  -- ^ the second argument of the algorithm, optional, set to 0 to ignore
  -> Int
  -- ^ the third argument of the algorithm, optional, set to 0 to ignore
  -> Int
  -- ^ length of output key
  -> V.Bytes
  -- ^ passphrase
  -> V.Bytes
  -- ^ salt
  -> IO V.Bytes
pwdHash algo p1 op2 op3 siz pwd s = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
      withPrimVectorUnsafe s $ \s' sOff sLen -> do
        (b, _) <- allocPrimVectorUnsafe @Word8 siz $ \buf ->
          throwBotanIfMinus_ (hs_botan_pwdhash algo' p1 op2 op3 buf (fromIntegral siz) pwd' ppOff ppLen s' sOff sLen)
        return b

-- | Derive a key from a passphrase using the given PBKDF algorithm.
pwdHashTimed
  :: CBytes
  -- ^ the name of the given PBKDF algorithm
  -> Int
  -- ^ run until milliseconds have passwd
  -> Int
  -- ^ the first argument of algorithm
  -> Int
  -- ^ the second argument of the algorithm, optional, set to 0 to ignore
  -> Int
  -- ^ the third argument of the algorithm, optional, set to 0 to ignore
  -> Int
  -- ^ length of output key
  -> V.Bytes
  -- ^ passphrase
  -> V.Bytes
  -- ^ salt
  -> IO V.Bytes
pwdHashTimed algo msec p1 op2 op3 siz pwd s = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
      withPrimVectorUnsafe s $ \s' sOff sLen -> do
        (b, _) <- allocPrimVectorUnsafe @Word8 siz $ \buf -> do
          (_, b') <- allocPrimArrayUnsafe @Int 3 $ \pArr ->
            throwBotanIfMinus_ (hs_botan_pwdhash_timed algo' msec pArr p1 op2 op3 buf (fromIntegral siz) pwd' ppOff ppLen s' sOff sLen)
          return b'
        return b
