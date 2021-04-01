module Z.Crypto.PasswdHash where

import Z.Botan.Exception (throwBotanIfMinus_)
import Z.Botan.FFI (botan_bcrypt_generate, botan_bcrypt_is_valid)
import Z.Crypto.RNG (RNG, withRNG)
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign (allocPrimUnsafe, allocPrimVectorUnsafe)

-- | Create a password hash using Bcrypt.
newBcrypt ::
  -- | Password.
  CBytes ->
  RNG ->
  -- | Work factors (4 < n < 18).
  Int ->
  IO V.Bytes
newBcrypt passwd rng n = do
  withCBytesUnsafe passwd $ \passwd' ->
    withRNG rng $ \rng' -> do
      (a, _) <- allocPrimVectorUnsafe 64 $ \ret -> do
        (a', _) <- allocPrimUnsafe @Int $ \len ->
          throwBotanIfMinus_ $ botan_bcrypt_generate ret len passwd' rng' n 0
        pure a'
      return a

-- | Check a previously created password hash.
isValidBcrypt ::
  -- | Password.
  CBytes ->
  -- | Hash.
  CBytes ->
  IO Bool
isValidBcrypt passwd hash = do
  withCBytesUnsafe passwd $ \passwd' ->
    withCBytesUnsafe hash $ \hash' -> do
      ret <- botan_bcrypt_is_valid passwd' hash'
      if ret == 0 then return True else return False
