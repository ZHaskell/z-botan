module Z.Crypto.PBKDF where

import Data.Word (Word8)
import Z.Botan.FFI (hs_botan_pwdhash, hs_botan_pwdhash_timed)
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign
  ( allocPrimArrayUnsafe,
    allocPrimVectorUnsafe,
    withPrimVectorUnsafe,
  )

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
  -> IO Int
pwdHash algo p1 op2 op3 siz pwd s = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
      withPrimVectorUnsafe s $ \s' sOff sLen -> do
        (_, b) <- allocPrimVectorUnsafe @Word8 siz $ \buf ->
          hs_botan_pwdhash algo' p1 op2 op3 buf (fromIntegral siz) pwd' ppOff ppLen s' sOff sLen
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
  -> IO Int
pwdHashTimed algo msec p1 op2 op3 siz pwd s = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
      withPrimVectorUnsafe s $ \s' sOff sLen -> do
        (_, b) <- allocPrimVectorUnsafe @Word8 siz $ \buf -> do
          (_, b') <- allocPrimArrayUnsafe @Int 3 $ \pArr ->
            hs_botan_pwdhash_timed algo' msec pArr p1 op2 op3 buf (fromIntegral siz) pwd' ppOff ppLen s' sOff sLen
          return b'
        return b
