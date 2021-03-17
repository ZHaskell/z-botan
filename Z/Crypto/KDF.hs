module Z.Crypto.KDF where

import Data.Word (Word8)
import Z.Botan.FFI (hs_botan_kdf)
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign (allocPrimVectorUnsafe, withPrimVectorUnsafe)

kdf ::
  -- | the name of the given PBKDF algorithm
  CBytes ->
  -- | length of output key
  Int ->
  -- | passphrase
  V.Bytes ->
  -- | salt
  V.Bytes ->
  IO Int
kdf algo siz pwd salt = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' secretOff secretLen ->
      withPrimVectorUnsafe salt $ \salt' saltOff saltLen -> do
        (_, b) <- allocPrimVectorUnsafe @Word8 siz $ \buf ->
          hs_botan_kdf algo' buf (fromIntegral siz) pwd' secretOff secretLen salt' saltOff saltLen
        return b
