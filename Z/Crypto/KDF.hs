module Z.Crypto.KDF where

import Data.Word (Word8)
import Z.Botan.FFI (hs_botan_kdf)
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign (allocPrimVectorUnsafe, withPrimVectorUnsafe)

-- | Derive a key using the given KDF algorithm.
kdf
  :: CBytes
  -- ^ the name of the given PBKDF algorithm
  -> Int
  -- ^ length of output key
  -> V.Bytes
  -- ^ passphrase
  -> V.Bytes
  -- ^ salt
  -> IO Int
kdf algo siz pwd salt = do
  withCBytesUnsafe algo $ \algo' ->
    withPrimVectorUnsafe pwd $ \pwd' secretOff secretLen ->
      withPrimVectorUnsafe salt $ \salt' saltOff saltLen -> do
        (_, b) <- allocPrimVectorUnsafe @Word8 siz $ \buf ->
          hs_botan_kdf algo' buf (fromIntegral siz) pwd' secretOff secretLen salt' saltOff saltLen
        return b
