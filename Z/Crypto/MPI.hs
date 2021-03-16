module Z.Crypto.MPI
  ( -- * RNG
    MPI, fromCInt, toWord32, byteSize, bitSize,
    toHex, toDecimal, fromHex, fromDecimal
  ) where

import           Control.Monad
import           Data.Bits          hiding (bitSize)
import           Data.Word
import           GHC.Generics
import           System.IO.Unsafe
import           Z.Data.ASCII
import           Z.Botan.FFI
import           Z.Botan.Exception
import           Z.Data.JSON         (JSON)
import qualified Z.Data.Array       as A
import qualified Z.Data.Builder     as B
import qualified Z.Data.Parser      as P
import qualified Z.Data.Vector      as V
import qualified Z.Data.Vector.Base as V
import qualified Z.Data.Text        as T
import qualified Z.Data.Text.Base   as T
import           Z.Crypto.RNG
import           Z.Foreign

-- | Opaque Botan Multiple Precision Integers.
newtype MPI = MPI BotanStruct

instance Show MPI where
    show = T.toString

instance T.Print MPI where
    toUTF8BuilderP _  = toDecimal

newMPI :: (BotanStructT -> IO a) -> IO MPI
newMPI f = do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    withBotanStruct mp f
    return (MPI mp)

unsafeWithMPI :: MPI -> (BotanStructT -> IO a) -> a
unsafeWithMPI (MPI bts) f = unsafeDupablePerformIO (withBotanStruct bts f)

unsafeNewMPI :: (BotanStructT -> IO a) -> MPI
unsafeNewMPI f = unsafeDupablePerformIO $ do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    withBotanStruct mp f
    return (MPI mp)

unsafeNewMPI' :: (BotanStructT -> IO a) -> (MPI, a)
unsafeNewMPI' f = unsafeDupablePerformIO $ do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    r <- withBotanStruct mp f
    return (MPI mp, r)

-- | Get 'MPI' 's byte size.
byteSize :: MPI -> Int
byteSize mp = fromIntegral @CSize . fst . unsafeWithMPI mp $ \ bts ->
    allocPrimUnsafe (botan_mp_num_bytes bts)

-- | Get 'MPI' 's bit size.
bitSize :: MPI -> Int
bitSize mp = fromIntegral @CSize . fst . unsafeWithMPI mp $ \ bts ->
    allocPrimUnsafe (botan_mp_num_bits bts)

-- | Set 'MPI' from an integer value.
fromCInt :: CInt -> MPI
fromCInt x = unsafeNewMPI $ \ bts ->
    botan_mp_set_from_int bts x

-- | Convert a MPI to 'Word32'.
toWord32 :: HasCallStack => MPI -> Word32
toWord32 mp = fst . unsafeWithMPI mp $ \ bts ->
    allocPrimUnsafe (botan_mp_to_uint32 bts)

-- | Write a 'MPI' in decimal format.
toDecimal :: MPI -> B.Builder ()
toDecimal mp@(MPI bts) =
    -- botan write \NUL terminator
    B.ensureN (byteSize mp * 3 + 1) $ \ (MutablePrimArray mba#) off ->
        withBotanStruct bts $ \ btst -> do
            hs_botan_mp_to_dec btst mba# off

-- | Parse a 'MPI' in decimal format.
fromDecimal :: P.Parser MPI
fromDecimal = do
    v@(V.PrimVector (A.PrimArray ba#) s l) <- P.takeWhile1 isDigit
    let (x, r) = unsafeNewMPI' $ \ bts -> hs_botan_mp_set_from_dec bts ba# s l
    if (r < 0)
    then P.fail' $ "wrong decimal integer: " <> T.toText v
    else return x

-- | Write a 'MPI' in hexadecimal format(without '0x' prefix).
toHex :: MPI -> B.Builder ()
toHex mp@(MPI bts) =
    -- botan write \NUL terminator
    let !siz = byteSize mp `unsafeShiftL` 1
    in B.ensureN (siz + 1) $ \ (MutablePrimArray mba#) off ->
        withBotanStruct bts $ \ btst -> do
            hs_botan_mp_to_hex btst mba# off
            return (off+siz)

-- | Parse a 'MPI' in hexadecimal format(without '0x' prefix).
fromHex :: P.Parser MPI
fromHex = do
    v@(V.PrimVector (A.PrimArray ba#) s l) <- P.takeWhile1 isHexDigit
    let (x, r) = unsafeNewMPI' $ \ bts -> hs_botan_mp_set_from_hex bts ba# s l
    if (r < 0)
    then P.fail' $ "wrong hexadecimal integer: " <> T.toText v
    else return x
