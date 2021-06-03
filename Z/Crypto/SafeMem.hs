module Z.Crypto.SafeMem (
  -- * Password
    Password, mkPassword, mkPasswordMaybe, passwordSize, passwordToText
  , withPasswordUnsafe, withPasswordSafe
  , InvalidPasswordException(..)
  -- * Nonce
  , Nonce, rand96bitNonce, rand128bitNonce, rand192bitNonce
  , cnt32bitNonce, cnt64bitNonce
  -- * CEBytes
  , CEBytes(..), ceBytesSize, ceBytesBitSize, newCEBytesUnsafe, newCEBytesSafe, ceBytes, unCEBytes
  -- * Secret
  , Secret, secretSize, secretBitSize, unsafeSecretFromBytes, unsafeSecretToBytes
  , newSecret, withSecret
  ) where

import           Control.Monad.Primitive
import           Data.Bits
import           Data.Char
import           Data.Int
import           Data.String
import           Data.Word
import           GHC.Prim
import           GHC.Ptr
import           Z.Botan.FFI
import           Z.Crypto.RNG
import qualified Z.Data.Builder          as B
import qualified Z.Data.CBytes           as CB
import qualified Z.Data.Text             as T
import qualified Z.Data.Text.Base        as T
import qualified Z.Data.Vector.Base      as V
import qualified Z.Data.Vector.Hex       as V
import           Z.Foreign
import           Z.IO.Exception
import           System.IO.Unsafe

-- | A type for human readable, it have
--
-- The 'Key' have the properties that:
--
-- * It's assumed to be UTF8 encoded and normalized, and does not have <https://en.wikipedia.org/wiki/Control_character control-characters>.
-- * There's no 'Eq' instance, you should always compare 'Password' via password hash.
-- * The 'Show' or 'Print' instance always print @"**PASSWORD**"@.
--
--  'Password' is not intented to be saved or transmitted, it's only useful when you want to validate a user's input against password hash.
--  See "Z.Crypto.PwdHash".
--
newtype Password = Password CB.CBytes

instance Show Password where
    show _ = "**PASSWORD**"

instance T.Print Password where
    {-# INLINABLE toUTF8BuilderP #-}
    toUTF8BuilderP _ _ = "**PASSWORD**"

instance IsString Password where
    {-# INLINABLE fromString #-}
    fromString = mkPassword . fromString

-- | Construct a password value from 'T.Text', if there're control-characters error will be thrown.
mkPassword :: HasCallStack => T.Text -> Password
{-# INLINABLE mkPassword #-}
mkPassword pwd = case mkPasswordMaybe pwd of
    Just r -> r
    _ -> throw (PasswordContainsControlCharacter callStack)

data InvalidPasswordException = PasswordContainsControlCharacter CallStack deriving Show
instance Exception InvalidPasswordException

-- | Construct a password value from 'Text', return 'Nothing' if contain control-characters.
mkPasswordMaybe :: T.Text -> Maybe Password
{-# INLINABLE mkPasswordMaybe #-}
mkPasswordMaybe pwd =
    case T.find isControl pwd of
        (_, Nothing) ->
            let pwd' = case T.isNormalized pwd of
                    T.NormalizedYes -> pwd
                    _ -> T.normalize pwd
            in Just $! Password (CB.fromText pwd')
        _ -> Nothing

-- | Byte size of a password.
passwordSize :: Password -> Int
{-# INLINABLE passwordSize #-}
passwordSize (Password pwd) = CB.length pwd

-- | Get plaintext of a password.
passwordToText :: Password -> T.Text
{-# INLINABLE passwordToText #-}
passwordToText (Password pwd) = T.Text (CB.toBytes pwd)

-- | Use password as null-terminated @const char*@, USE WITH UNSAFE FFI ONLY, PLEASE DO NOT MODIFY THE CONTENT.
withPasswordUnsafe :: Password -> (BA# Word8 -> IO r) -> IO r
{-# INLINABLE withPasswordUnsafe #-}
withPasswordUnsafe (Password pwd) = CB.withCBytesUnsafe pwd

-- | Use password as null-terminated @const char*@, PLEASE DO NOT MODIFY THE CONTENT.
withPasswordSafe :: Password -> (Ptr Word8 -> IO r) -> IO r
{-# INLINABLE withPasswordSafe #-}
withPasswordSafe (Password pwd) = CB.withCBytes pwd

--------------------------------------------------------------------------------

-- | A value used only once in AEAD modes.
--
-- We use also this type to represent IV(initialization vector) for stream ciphers, but the way a nonce is generated is different:
-- random IV is one generation choice which is usually fine, while Nonce can also be a counter, which is not ok for CBC mode.
--
-- Some common nonce size:
--
-- * 96bit for GCM AEAD, ChaCha20Poly1305.
-- * 128bit for XChaCha20Poly1305.
-- * Block size for CBC IV(e.g. 128 bits for AES).
--
type Nonce = V.Bytes

-- | Get 64-bit random nonce.
rand96bitNonce :: RNG -> IO Nonce
{-# INLINABLE rand96bitNonce #-}
rand96bitNonce rng = getRandom rng 12

-- | Get 128-bit random nonce.
rand128bitNonce :: RNG -> IO Nonce
{-# INLINABLE rand128bitNonce #-}
rand128bitNonce rng = getRandom rng 16

-- | Get 192-bit random nonce.
rand192bitNonce :: RNG -> IO Nonce
{-# INLINABLE rand192bitNonce #-}
rand192bitNonce rng = getRandom rng 24

-- | Get 32bit nonce from counter.
cnt32bitNonce :: Int32 -> Nonce
{-# INLINABLE cnt32bitNonce #-}
cnt32bitNonce c = B.build $ B.encodePrimBE c

-- | Get 64bit nonce from counter.
cnt64bitNonce :: Int64 -> Nonce
{-# INLINABLE cnt64bitNonce #-}
cnt64bitNonce c = B.build $ B.encodePrimBE c

--------------------------------------------------------------------------------

-- | Constant-time equal comparing bytes.
--
-- It comes with following property:
--
-- * The 'Eq' instance gives you constant-time compare.
-- * The 'Show' and 'T.Print' instances give you hex encoding.
--
newtype CEBytes = CEBytes (PrimArray Word8)

ceBytesSize :: CEBytes -> Int
{-# INLINABLE ceBytesSize #-}
ceBytesSize (CEBytes d) = sizeofPrimArray d

ceBytesBitSize :: CEBytes -> Int
{-# INLINABLE ceBytesBitSize #-}
ceBytesBitSize (CEBytes d) = 8 * (V.length d)

instance Eq CEBytes where
    {-# INLINABLE (==) #-}
    (CEBytes pa@(PrimArray ba#)) == (CEBytes pb@(PrimArray bb#)) =
        la == lb && botan_constant_time_compare_ba ba# bb# (fromIntegral la) == 0
      where
        la = sizeofPrimArray pa
        lb = sizeofPrimArray pb

instance Show CEBytes where
    show = T.toString

instance T.Print CEBytes where
    toUTF8BuilderP _ = V.hexEncodeBuilder True . unCEBytes

-- | Create a ceBytes from unsafe FFI.
newCEBytesUnsafe :: Int -> (MBA# Word8 -> IO r) -> IO CEBytes
{-# INLINABLE newCEBytesUnsafe #-}
newCEBytesUnsafe len f = do
    (d, _) <- allocPrimArrayUnsafe len f
    pure (CEBytes d)

-- | Create a ceBytes from safe FFI.
newCEBytesSafe :: Int -> (Ptr Word8 -> IO r) -> IO CEBytes
{-# INLINABLE newCEBytesSafe #-}
newCEBytesSafe len f = do
    (d, _) <- allocPrimArraySafe len f
    pure (CEBytes d)

-- | Create a 'CEBytes' from 'V.Bytes'.
ceBytes :: V.Bytes -> CEBytes
{-# INLINABLE ceBytes #-}
ceBytes = CEBytes . V.arrVec

-- | Get 'CEBytes' 's content as 'V.Bytes', by doing this you lose the constant-time comparing.
unCEBytes :: CEBytes -> V.Bytes
{-# INLINABLE unCEBytes #-}
unCEBytes (CEBytes d) = V.arrVec d

--------------------------------------------------------------------------------

-- | Memory allocated by locked allocator and will be zeroed after used.
--
-- * It's allocated by botan's locking allocator(which means it will not get swapped to disk) if possible.
-- * It will zero the memory it used once get GCed.
-- * The 'Eq' instance gives you constant-time compare.
-- * The 'Show' or 'Print' instance always print @"**SECRET**"@.
--
--  'Secret' is not intented to be saved or transmitted, there're several way to obtain a 'Secret':
--
--  + Use 'unsafeSecretFromBytes' to convert a piece of 'Bytes' to 'Secret'.
--  + Use key-exchanges from 'Z.Crypto.PubKey'.
--  + Unwrap a key, see 'Z.Crypto.KeyWrap'.
--
newtype Secret = Secret (PrimArray (Ptr Word8))

instance Show Secret where
    show _ = "**SECRET**"

instance T.Print Secret where
    {-# INLINABLE toUTF8BuilderP #-}
    toUTF8BuilderP _ _ = "**SECRET**"

-- | This instance will break the no-tracing property by saving secret in compiled and loaded binary.
instance IsString Secret where
    {-# INLINABLE fromString #-}
    fromString = unsafePerformIO . unsafeSecretFromBytes . fromString

-- | Constant-time compare
instance Eq Secret where
    {-# INLINABLE (==) #-}
    a@(Secret pa) == b@(Secret pb) =
        la == lb && botan_constant_time_compare (indexPrimArray pa 0) (indexPrimArray pb 0) (fromIntegral la) == 0
      where
        la = secretSize a
        lb = secretSize b

-- | Get secret key's byte length.
secretSize :: Secret -> Int
{-# INLINABLE secretSize #-}
secretSize (Secret pa) = (indexPrimArray pa 1) `minusPtr` (indexPrimArray pa 0)

-- | Get secret key's bit size.
secretBitSize :: Secret -> Int
{-# INLINABLE secretBitSize #-}
secretBitSize k = secretSize k `unsafeShiftL` 3

-- | Unsafe convert a 'V.Bytes' to a 'Secret'.
--
-- Note the original 'V.Bytes' may get moved by GC or swapped to disk, which may defeat the purpose of using a 'Secret'.
unsafeSecretFromBytes :: V.Bytes -> IO Secret
{-# INLINABLE unsafeSecretFromBytes #-}
unsafeSecretFromBytes (V.PrimVector pa poff plen) = newSecret plen $ \ p ->
    copyPrimArrayToPtr p pa poff plen

-- | Unsafe convert a 'V.Bytes' from a 'Secret'.
--
-- Note the result 'V.Bytes' may get moved by GC or swapped to disk, which may defeat the purpose of using a 'Secret'.
unsafeSecretToBytes :: Secret -> IO V.Bytes
{-# INLINABLE unsafeSecretToBytes #-}
unsafeSecretToBytes key = withSecret key $ \ p len ->
    let len' = fromIntegral len
    in fst <$> allocPrimVectorUnsafe len' (\ p' ->
        copyPtrToMutablePrimArray (MutablePrimArray p') 0 p len')

-- | Initialize a 'Secret' which pass an allocated pointer pointing to zeros to a init function.
newSecret :: Int -> (Ptr Word8 -> IO r) -> IO Secret
{-# INLINABLE newSecret #-}
newSecret len f = mask_ $ do
    mpa <- newPrimArray 2
    p@(Ptr addr#) <- hs_botan_allocate_memory len
    _ <- f p `onException` hs_botan_deallocate_memory (p `plusPtr` len) p
    let !p'@(Ptr addr'#) = p `plusPtr` len
    writePrimArray mpa 0 p
    writePrimArray mpa 1 p'
    pa@(PrimArray ba#) <- unsafeFreezePrimArray mpa
    primitive_ $ \ s0# ->
        let !(# s1#, w# #) = mkWeakNoFinalizer# ba# () s0#
            !(# s2#, _ #) = addCFinalizerToWeak# fin# addr# 1# addr'# w# s1#
        in s2#
    return (Secret pa)
  where
    !(FunPtr fin#) = hs_botan_deallocate_memory_p

-- | Use 'Secret' as a @const char*@, PLEASE DO NOT MODIFY THE CONTENT.
--
withSecret :: Secret -> (Ptr Word8 -> CSize -> IO r) -> IO r
{-# INLINABLE withSecret #-}
withSecret (Secret pa@(PrimArray ba#)) f = do
    let p   = indexPrimArray pa 0
        p'  = indexPrimArray pa 1
    x <- f p (fromIntegral $ p' `minusPtr` p)
    primitive_ (touch# ba#)
    return x
