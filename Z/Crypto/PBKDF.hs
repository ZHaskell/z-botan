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

pwdHash ::
  -- | the name of the given PBKDF algorithm
  CBytes ->
  -- | the first argument of algorithm
  Int ->
  -- | the second argument of the algorithm, optional, set to 0 to ignore
  Int ->
  -- | the third argument of the algorithm, optional, set to 0 to ignore
  Int ->
  -- | length of output key
  Int ->
  -- | passphrase
  V.Bytes ->
  -- | salt
  V.Bytes ->
  IO Int
pwdHash algo p1 op2 op3 siz pwd s = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
      withPrimVectorUnsafe s $ \s' sOff sLen -> do
        (_, b) <- allocPrimVectorUnsafe @Word8 siz $ \buf ->
          hs_botan_pwdhash algo' p1 op2 op3 buf (fromIntegral siz) pwd' ppOff ppLen s' sOff sLen
        return b

pwdHashTimed ::
  -- | the name of the given PBKDF algorithm
  CBytes ->
  -- | run until milliseconds have passwd
  Int ->
  -- | the first argument of algorithm
  Int ->
  -- | the second argument of the algorithm, optional, set to 0 to ignore
  Int ->
  -- | the third argument of the algorithm, optional, set to 0 to ignore
  Int ->
  -- | length of output key
  Int ->
  -- | passphrase
  V.Bytes ->
  -- | salt
  V.Bytes ->
  IO Int
pwdHashTimed algo msec p1 op2 op3 siz pwd s = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' ppOff ppLen ->
      withPrimVectorUnsafe s $ \s' sOff sLen -> do
        (_, b) <- allocPrimVectorUnsafe @Word8 siz $ \buf -> do
          (_, b') <- allocPrimArrayUnsafe @Int 3 $ \pArr ->
            hs_botan_pwdhash_timed algo' msec pArr p1 op2 op3 buf (fromIntegral siz) pwd' ppOff ppLen s' sOff sLen
          return b'
        return b
