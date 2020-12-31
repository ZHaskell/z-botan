module Z.Botan.FFI where

import           Data.Word
import           Foreign.ForeignPtr
import           Foreign.Ptr
import           GHC.Generics
import           GHC.Prim           (mkWeak##)
import           GHC.Types          (IO (..))
import           Z.IO.Exception
import           Z.Botan.Exception
import           Z.Data.CBytes
import           Z.Data.JSON         (EncodeJSON, ToValue, FromValue)
import qualified Z.Data.Vector      as V
import qualified Z.Data.Text        as T
import           Z.Foreign

#include "hs_botan.h"

--------------------------------------------------------------------------------

foreign import ccall unsafe hs_botan_hex_encode :: BA## Word8 -> Int -> Int -> MBA## Word8 -> IO ()
foreign import ccall unsafe hs_botan_hex_encode_lower :: BA## Word8 -> Int -> Int -> MBA## Word8 -> IO ()
foreign import ccall unsafe hs_botan_hex_decode :: BA## Word8 -> Int -> Int -> MBA## Word8 -> IO ()

--------------------------------------------------------------------------------

-- | Internal type to representation botan struct, botan_xxx_t is always pointer type.
newtype BotanStruct = BotanStruct (ForeignPtr BotanStruct)
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass T.Print

type BotanStructT = Ptr BotanStruct

withBotanStruct :: BotanStruct -> (BotanStructT -> IO a) -> IO a
withBotanStruct (BotanStruct fp) = withForeignPtr fp

newBotanStruct :: HasCallStack
               => (MBA## BotanStructT -> IO CInt)  -- ^ init function
               -> FunPtr (BotanStructT -> IO ())     -- ^ destroy function pointer
               -> IO BotanStruct
newBotanStruct init_ destroy = do
    (p, _) <- allocPrimUnsafe $ \ pp -> throwBotanIfMinus_ (init_ pp)
    BotanStruct <$> newForeignPtr destroy p

--------------------------------------------------------------------------------

foreign import ccall unsafe botan_rng_init :: MBA## BotanStructT -> BA## Word8 -> IO CInt
foreign import ccall unsafe "&botan_rng_destroy" botan_rng_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_rng_get :: BotanStructT -> MBA## Word8 -> CSize -> IO CInt
foreign import ccall unsafe botan_rng_reseed :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_rng_reseed_from_rng :: BotanStructT -> BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe hs_botan_rng_add_entropy :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt

--------------------------------------------------------------------------------

foreign import ccall unsafe botan_block_cipher_init :: MBA## BotanStructT -> BA## Word8 -> IO CInt
foreign import ccall unsafe "&botan_block_cipher_destroy"
    botan_block_cipher_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_block_cipher_block_size :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_block_cipher_get_keyspec :: BotanStructT 
                                                           -> MBA## Int   -- ^ minimum_keylength
                                                           -> MBA## Int   -- ^ maximum_keylength
                                                           -> MBA## Int   -- ^ keylength_modulo
                                                           -> IO CInt
foreign import ccall unsafe botan_block_cipher_clear :: BotanStructT -> IO CInt
foreign import ccall unsafe hs_botan_block_cipher_set_key
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe hs_botan_block_cipher_encrypt_blocks
    :: BotanStructT 
    -> BA## Word8   -- ^ in_buf
    -> Int          -- ^ in offset
    -> MBA## Word8  -- ^ out buffer
    -> Int          -- ^ number of block
    -> IO CInt
foreign import ccall unsafe hs_botan_block_cipher_decrypt_blocks
    :: BotanStructT 
    -> BA## Word8   -- ^ in_buf
    -> Int          -- ^ in offset
    -> MBA## Word8  -- ^ out buffer
    -> Int          -- ^ number of block
    -> IO CInt

--------------------------------------------------------------------------------

foreign import ccall unsafe botan_hash_init :: MBA## BotanStructT -> BA## Word8 -> Word32 -> IO CInt
foreign import ccall unsafe "&botan_hash_destroy"
    botan_hash_destroy ::FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_hash_copy_state :: MBA## BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_hash_clear :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_hash_output_length :: BotanStructT -> MBA## CSize -> IO CInt
foreign import ccall unsafe hs_botan_hash_update :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe botan_hash_final :: BotanStructT -> MBA## Word8 -> IO CInt

--------------------------------------------------------------------------------

data CipherDirection = CipherEncrypt | CipherDecrypt
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (T.Print, EncodeJSON, ToValue, FromValue)

cipherDirectionToFlag ::  CipherDirection -> Word32
cipherDirectionToFlag CipherEncrypt = #const BOTAN_CIPHER_INIT_FLAG_ENCRYPT
cipherDirectionToFlag CipherDecrypt = #const BOTAN_CIPHER_INIT_FLAG_DECRYPT

foreign import ccall unsafe botan_cipher_init :: MBA## BotanStructT -> BA## Word8 -> Word32 -> IO CInt
foreign import ccall unsafe "&botan_cipher_destroy"
    botan_cipher_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_cipher_clear :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_cipher_reset :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_cipher_get_keyspec :: BotanStructT 
                                                     -> MBA## Int   -- ^ minimum_keylength
                                                     -> MBA## Int   -- ^ maximum_keylength
                                                     -> MBA## Int   -- ^ keylength_modulo
                                                     -> IO CInt
foreign import ccall unsafe hs_botan_cipher_set_key
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe hs_botan_cipher_start
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe hs_botan_cipher_update
    :: BotanStructT 
    -> Word32       -- ^ flag
    -> MBA## Word8  -- ^ output
    -> Int          -- ^ output size
    -> MBA## CSize  -- ^ output written
    -> BA## Word8   -- ^ input
    -> Int          -- ^ input offset
    -> Int          -- ^ input len
    -> MBA## CSize  -- ^ input consumed
    -> IO CInt
foreign import ccall unsafe hs_botan_cipher_set_associated_data
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt

foreign import ccall unsafe botan_cipher_valid_nonce_length :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_cipher_get_default_nonce_length :: BotanStructT -> MBA## Int -> IO CInt
foreign import ccall unsafe botan_cipher_get_update_granularity :: BotanStructT -> MBA## Int -> IO CInt
foreign import ccall unsafe botan_cipher_get_tag_length :: BotanStructT -> MBA## Int -> IO CInt

--------------------------------------------------------------------------------
