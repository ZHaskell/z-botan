{-|
Module      : Z.Botan.Errno
Description : Errno provided by botan
Copyright   : (c) Dong Han, 2020 - 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

INTERNAL MODULE, provides all botan FFI defs.

-}

module Z.Botan.FFI where

import           Data.Word
import           Data.Bits
import           Foreign.Ptr
import           GHC.Generics
import           Z.IO.Exception
import           Z.Botan.Exception
import           Z.Data.CBytes
import           Z.Data.JSON            (JSON)
import qualified Z.Data.Vector          as V
import qualified Z.Data.Vector.Extra    as V
import qualified Z.Data.Text            as T
import           Z.Foreign
import           Z.Foreign.CPtr

#include <botan/ffi.h>

--------------------------------------------------------------------------------

foreign import ccall unsafe hs_botan_allocate_memory :: Int -> IO (Ptr Word8)
foreign import ccall unsafe "&hs_botan_deallocate_memory" hs_botan_deallocate_memory_p :: FunPtr (Ptr Word8 -> Ptr Word8 -> IO ())
foreign import ccall unsafe hs_botan_deallocate_memory :: Ptr Word8 -> Ptr Word8 -> IO ()

foreign import ccall unsafe "botan_constant_time_compare" botan_constant_time_compare_ba :: BA## Word8 -> BA## Word8 -> CSize -> CInt
foreign import ccall unsafe botan_constant_time_compare :: Ptr Word8 -> Ptr Word8 -> CSize -> CInt


allocBotanBufferUTF8Unsafe :: (HasCallStack, Integral r)
                           => Int -> (MBA## Word8 -> MBA## CSize -> IO r) -> IO T.Text
allocBotanBufferUTF8Unsafe len f = T.validate . V.unsafeInit <$> allocBotanBufferUnsafe len f

allocBotanBufferUnsafe :: (HasCallStack, Integral r)
                       => Int -> (MBA## Word8 -> MBA## CSize -> IO r) -> IO V.Bytes
allocBotanBufferUnsafe len f = do
    (bs, (r1, r2)) <- allocPrimVectorUnsafe len (\ buf ->
        withPrimUnsafe (fromIntegral len :: CSize) (\ size ->
            f buf size))
    if fromIntegral r2 == BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE
    then allocBotanBufferUnsafe (len `unsafeShiftL` 1) f
    else if r2 >= 0
        then return $! V.unsafeTake (fromIntegral r1) bs
        else throwBotanError (fromIntegral r2)

--------------------------------------------------------------------------------

-- | Internal type to representation botan struct, botan_xxx_t is always pointer type.

type BotanStruct = CPtr ()
type BotanStructT = Ptr ()

withBotanStruct :: BotanStruct -> (BotanStructT -> IO a) -> IO a
withBotanStruct = withCPtr

newBotanStruct :: HasCallStack
               => (MBA## BotanStructT -> IO CInt)   -- ^ init function
               -> FunPtr (BotanStructT -> IO a)     -- ^ destroy function pointer
               -> IO BotanStruct
newBotanStruct init_ destroy = do
    (bts, _) <- newCPtrUnsafe (\ pp -> throwBotanIfMinus_ (init_ pp)) destroy
    return bts

newBotanStruct' :: HasCallStack
                => (Ptr BotanStructT -> IO CInt)    -- ^ init function
                -> FunPtr (BotanStructT -> IO a)    -- ^ destroy function pointer
                -> IO BotanStruct
newBotanStruct' init_ destroy = do
    (bts, _) <- newCPtr (\ pp -> throwBotanIfMinus_ (init_ pp)) destroy
    return bts

--------------------------------------------------------------------------------
-- RNG

foreign import ccall unsafe botan_rng_init :: MBA## BotanStructT -> BA## Word8 -> IO CInt
foreign import ccall unsafe "&botan_rng_destroy" botan_rng_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_rng_get :: BotanStructT -> MBA## Word8 -> CSize -> IO CInt
foreign import ccall unsafe botan_rng_reseed :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_rng_reseed_from_rng :: BotanStructT -> BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe hs_botan_rng_add_entropy :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt


--------------------------------------------------------------------------------
-- MPI

foreign import ccall unsafe botan_mp_init :: MBA## BotanStructT -> IO CInt
foreign import ccall unsafe "&botan_mp_destroy" botan_mp_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_mp_set_from_int :: BotanStructT -> CInt -> IO CInt
foreign import ccall unsafe botan_mp_set_from_mp :: BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_num_bytes :: BotanStructT -> MBA## CSize -> IO CInt
foreign import ccall unsafe botan_mp_num_bits :: BotanStructT -> MBA## CSize -> IO CInt
foreign import ccall unsafe hs_botan_mp_to_hex :: BotanStructT -> MBA## Word8 -> Int -> IO CInt
foreign import ccall unsafe hs_botan_mp_to_dec :: BotanStructT -> MBA## Word8 -> Int -> IO Int
foreign import ccall unsafe hs_botan_mp_set_from_hex :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe hs_botan_mp_set_from_dec :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe hs_botan_mp_to_bin :: BotanStructT -> MBA## Word8 -> Int -> IO CInt
foreign import ccall unsafe hs_botan_mp_from_bin :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe botan_mp_flip_sign :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_add :: BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_sub :: BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_mul :: BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_div :: BotanStructT -> BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_mod_mul :: BotanStructT -> BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_equal :: BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_is_zero :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_is_odd :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_is_even :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_is_positive :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_is_negative :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_to_uint32 :: BotanStructT -> MBA## Word32 -> IO CInt
foreign import ccall unsafe botan_mp_cmp :: MBA## CInt -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_swap :: BotanStructT -> BotanStructT -> IO ()
foreign import ccall unsafe botan_mp_powmod :: BotanStructT -> BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_lshift :: BotanStructT -> BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_mp_rshift :: BotanStructT -> BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_mp_mod_inverse :: BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_rand_bits :: BotanStructT -> BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_mp_rand_range :: BotanStructT -> BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_gcd :: BotanStructT -> BotanStructT -> BotanStructT -> IO CInt
foreign import ccall unsafe botan_mp_is_prime :: BotanStructT -> BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_mp_get_bit :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_mp_set_bit :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_mp_clear_bit :: BotanStructT -> CSize -> IO CInt

--------------------------------------------------------------------------------

{-

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
foreign import ccall unsafe botan_block_cipher_set_key :: BotanStructT -> Ptr Word8 -> CSize -> IO CInt
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
    deriving anyclass (T.Print, JSON)

cipherDirectionToFlag ::  CipherDirection -> Word32
cipherDirectionToFlag CipherEncrypt = #const BOTAN_CIPHER_INIT_FLAG_ENCRYPT
cipherDirectionToFlag CipherDecrypt = #const BOTAN_CIPHER_INIT_FLAG_DECRYPT

foreign import ccall unsafe botan_cipher_init :: MBA## BotanStructT -> BA## Word8 -> Word32 -> IO CInt
foreign import ccall unsafe "&botan_cipher_destroy"
    botan_cipher_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_cipher_clear :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_cipher_get_keyspec :: BotanStructT
                                                     -> MBA## CSize   -- ^ minimum_keylength
                                                     -> MBA## CSize   -- ^ maximum_keylength
                                                     -> MBA## CSize   -- ^ keylength_modulo
                                                     -> IO CInt
foreign import ccall unsafe botan_cipher_set_key :: BotanStructT -> Ptr Word8 -> CSize -> IO CInt
foreign import ccall unsafe hs_botan_cipher_start
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt

foreign import ccall unsafe hs_botan_cipher_finish
    :: BotanStructT
    -> MBA## Word8  -- ^ output
    -> Int          -- ^ output size
    -> BA## Word8   -- ^ input
    -> Int          -- ^ input offset
    -> Int          -- ^ input len
    -> IO Int       -- ^ output written

foreign import ccall unsafe hs_botan_cipher_set_associated_data
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt

foreign import ccall unsafe botan_cipher_valid_nonce_length :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_cipher_get_default_nonce_length :: BotanStructT -> MBA## Int -> IO CInt
foreign import ccall unsafe botan_cipher_get_tag_length :: BotanStructT -> MBA## Int -> IO CInt
foreign import ccall unsafe hs_botan_cipher_output_size :: BotanStructT -> Int -> IO Int


foreign import ccall unsafe botan_stream_cipher_init :: MBA## BotanStructT -> BA## Word8 -> IO CInt
foreign import ccall unsafe "&botan_stream_cipher_destroy"
    botan_stream_cipher_destroy :: FunPtr (BotanStructT -> IO ())
foreign import ccall unsafe botan_stream_cipher_seek :: BotanStructT -> CSize -> IO CInt

foreign import ccall unsafe botan_stream_cipher_clear :: BotanStructT -> IO CInt
foreign import ccall unsafe botan_stream_cipher_get_keyspec :: BotanStructT
                                                     -> MBA## CSize   -- ^ minimum_keylength
                                                     -> MBA## CSize   -- ^ maximum_keylength
                                                     -> MBA## CSize   -- ^ keylength_modulo
                                                     -> IO CInt
foreign import ccall unsafe botan_stream_cipher_set_key :: BotanStructT -> Ptr Word8 -> CSize -> IO CInt
foreign import ccall unsafe hs_botan_stream_cipher_set_iv
    :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt
foreign import ccall unsafe hs_botan_stream_cipher_cipher
    :: BotanStructT
    -> MBA## Word8  -- ^ output
    -> BA## Word8   -- ^ input
    -> Int          -- ^ input offset
    -> Int          -- ^ input len
    -> IO CInt      

foreign import ccall unsafe botan_stream_cipher_write_keystream
    :: BotanStructT
    -> MBA## Word8  -- ^ output
    -> CSize        -- ^ output size
    -> IO CInt      

foreign import ccall unsafe botan_stream_cipher_valid_iv_length :: BotanStructT -> CSize -> IO CInt
foreign import ccall unsafe botan_stream_cipher_get_default_iv_length :: BotanStructT -> MBA## Int -> IO CInt

--------------------------------------------------------------------------------
-- PBKDF

foreign import ccall unsafe hs_botan_pwdhash :: BA## Word8
                                             -> Int -> Int -> Int
                                             -> Ptr Word8 -> Int                -- ^ output
                                             -> BA## Word8 -> Int               -- ^ passphrase
                                             -> BA## Word8 -> Int -> Int        -- ^ salt
                                             -> IO CInt

foreign import ccall unsafe hs_botan_pwdhash_timed :: BA## Word8
                                                   -> Int
                                                   -> Ptr Word8 -> Int          -- ^ output
                                                   -> BA## Word8 -> Int         -- ^ passphrase
                                                   -> BA## Word8 -> Int -> Int  -- ^ salt
                                                   -> IO CInt

foreign import ccall safe "hs_botan_pwdhash_timed"
    hs_botan_pwdhash_timed_safe :: Ptr Word8
                                -> Int
                                -> Ptr Word8 -> Int         -- ^ output
                                -> Ptr Word8 -> Int         -- ^ passphrase
                                -> Ptr Word8 -> Int -> Int  -- ^ salt
                                -> IO CInt

--------------------------------------------------------------------------------
-- KDF

foreign import ccall unsafe hs_botan_kdf :: BA## Word8
                                         -> Ptr Word8 -> CSize
                                         -> Ptr Word8 -> CSize
                                         -> BA## Word8 -> Int -> Int
                                         -> BA## Word8 -> Int -> Int
                                         -> IO CInt


--------------------------------------------------------------------------------
-- Password Hashing

foreign import ccall unsafe botan_bcrypt_generate :: MBA## Word8 -> MBA## CSize
                                                  -> BA## Word8
                                                  -> BotanStructT
                                                  -> Int
                                                  -> Word32
                                                  -> IO CInt

foreign import ccall unsafe hs_botan_bcrypt_is_valid :: BA## Word8 
                                                     -> BA## Word8 -> Int -> Int
                                                     -> IO CInt

---------------------------------------------------------------------------------
-- MAC

foreign import ccall unsafe botan_mac_init :: MBA## BotanStructT -> BA## Word8 -> Word32 -> IO CInt
foreign import ccall unsafe "&botan_mac_destroy" botan_mac_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_mac_output_length ::BotanStructT -> MBA## CSize -> IO CInt

foreign import ccall unsafe botan_mac_final :: BotanStructT -> MBA## Word8 -> IO CInt

foreign import ccall unsafe botan_mac_set_key :: BotanStructT -> Ptr Word8 -> CSize -> IO CInt

foreign import ccall unsafe hs_botan_mac_update :: BotanStructT -> BA## Word8 -> Int -> Int-> IO CInt

foreign import ccall unsafe hs_botan_mac_clear :: BotanStructT -> IO CInt

foreign import ccall unsafe hs_botan_mac_name ::  BotanStructT -> MBA## Word8 -> MBA## Int -> IO CInt

foreign import ccall unsafe hs_botan_mac_get_keyspec :: BotanStructT -> MBA## Int -> MBA## Int -> MBA## Int -> IO CInt

--------------------------------------------------------------------------------
-- Public Key Creation, Import and Export (at Z.Crypto.PubKey)

foreign import ccall safe botan_privkey_create :: Ptr BotanStructT    -- ^ botan_privkey_t* key
                                               -> Ptr Word8           -- ^ const char* algo_name
                                               -> Ptr Word8           -- ^ const char* algo_params
                                               -> BotanStructT        -- ^ botan_rng_t rng
                                               -> IO CInt

foreign import ccall unsafe hs_botan_privkey_load :: MBA## BotanStructT
                                                  -> BotanStructT
                                                  -> BA## Word8 -> Int -> Int
                                                  -> BA## Word8
                                                  -> IO CInt

foreign import ccall unsafe botan_privkey_export :: BotanStructT -- ^ botan_privkey_t key
                                                 -> MBA## Word8 -> MBA## CSize -- ^ uint8_t out[], size_t* out_len
                                                 -> Word32 -- ^ uint32_t flags
                                                 -> IO CInt

foreign import ccall unsafe botan_privkey_export_encrypted
    :: BotanStructT                     -- ^ botan_privkey_t key
    -> MBA## Word8 -> MBA## CSize       -- ^ uint8_t out[], size_t* out_len
    -> BotanStructT                     -- ^ botan_rng_t 
    -> BA## Word8                       -- ^ passphrase
    -> BA## Word8                       -- ^ encryption_algo, currently ignored by botan
    -> Word32                           -- ^ uint32_t flags
    -> IO CInt

foreign import ccall unsafe botan_privkey_export_pubkey :: MBA## BotanStructT
                                                        -> BotanStructT
                                                        -> IO CInt

foreign import ccall unsafe botan_privkey_get_field :: BotanStructT -- ^ botan_mp_t output
                                                    -> BotanStructT -- ^ botan_privkey_t key
                                                    -> BA## Word8 -- ^ const char* field_name
                                                    -> IO CInt

foreign import ccall unsafe "&botan_privkey_destroy" botan_privkey_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe hs_botan_pubkey_load :: MBA## BotanStructT -- ^ botan_pubkey_t* key
                                                 -> BA## Word8 -> Int -> Int
                                                 -> IO CInt

foreign import ccall unsafe botan_pubkey_export :: BotanStructT
                                                -> MBA## Word8 -> MBA## CSize
                                                -> Word32
                                                -> IO CInt

foreign import ccall unsafe botan_privkey_algo_name :: BotanStructT
                                                   -> MBA## Word8 -> MBA## CSize
                                                   -> IO CInt

foreign import ccall unsafe botan_pubkey_algo_name :: BotanStructT
                                                   -> MBA## Word8 -> MBA## CSize
                                                   -> IO CInt

foreign import ccall unsafe botan_pubkey_estimated_strength :: BotanStructT
                                                            -> MBA## CSize
                                                            -> IO CInt

foreign import ccall unsafe botan_pubkey_fingerprint :: BotanStructT
                                                     -> BA## Word8
                                                     -> MBA## Word8 -> MBA## CSize
                                                     -> IO CInt

foreign import ccall unsafe "&botan_pubkey_destroy" botan_pubkey_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_pubkey_get_field :: BotanStructT
                                                   -> BotanStructT
                                                   -> BA## Word8
                                                   -> IO CInt

--------------------------------------------------------------------------------
-- RSA specific functions


foreign import ccall unsafe botan_privkey_load_rsa :: MBA## BotanStructT
                                                   -> BotanStructT -> BotanStructT -> BotanStructT
                                                   -> IO CInt

foreign import ccall unsafe botan_pubkey_load_rsa :: MBA## BotanStructT
                                                  -> BotanStructT -> BotanStructT
                                                  -> IO CInt

--------------------------------------------------------------------------------
-- DSA specific functions

foreign import ccall unsafe botan_privkey_load_dsa :: MBA## BotanStructT
                                                   -> BotanStructT -> BotanStructT -> BotanStructT
                                                   -> BotanStructT
                                                   -> IO CInt

foreign import ccall unsafe botan_pubkey_load_dsa :: MBA## BotanStructT
                                                  -> BotanStructT -> BotanStructT -> BotanStructT
                                                  -> BotanStructT
                                                  -> IO CInt

--------------------------------------------------------------------------------
-- ElGamal specific functions

foreign import ccall unsafe botan_privkey_load_elgamal :: MBA## BotanStructT
                                                       -> BotanStructT -> BotanStructT -> BotanStructT
                                                       -> IO CInt

foreign import ccall unsafe botan_pubkey_load_elgamal :: MBA## BotanStructT
                                                      -> BotanStructT -> BotanStructT -> BotanStructT
                                                      -> IO CInt

--------------------------------------------------------------------------------
-- Diffie-Hellman specific functions

foreign import ccall unsafe botan_privkey_load_dh :: MBA## BotanStructT
                                                  -> BotanStructT -> BotanStructT -> BotanStructT
                                                  -> IO CInt

foreign import ccall unsafe botan_pubkey_load_dh :: MBA## BotanStructT
                                                 -> BotanStructT -> BotanStructT -> BotanStructT
                                                 -> IO CInt

--------------------------------------------------------------------------------
-- Public Key Encryption / Decryption

foreign import ccall unsafe botan_pk_op_encrypt_create :: MBA## BotanStructT
                                                       -> BotanStructT
                                                       -> BA## Word8
                                                       -> Word32
                                                       -> IO CInt

foreign import ccall unsafe "&botan_pk_op_encrypt_destroy" botan_pk_op_encrypt_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_pk_op_encrypt_output_length :: BotanStructT
                                                              -> CSize
                                                              -> MBA## CSize
                                                              -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_encrypt :: BotanStructT
                                                   -> BotanStructT
                                                   -> MBA## Word8 -> MBA## CSize
                                                   -> BA## Word8 -> Int -> Int
                                                   -> IO CInt

foreign import ccall unsafe botan_pk_op_decrypt_create :: MBA## BotanStructT
                                                       -> BotanStructT
                                                       -> BA## Word8
                                                       -> Word32
                                                       -> IO CInt

foreign import ccall unsafe "&botan_pk_op_decrypt_destroy" botan_pk_op_decrypt_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_pk_op_decrypt_output_length :: BotanStructT
                                                              -> CSize
                                                              -> MBA## CSize
                                                              -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_decrypt :: BotanStructT
                                                   -> MBA## Word8 -> MBA## CSize
                                                   -> BA## Word8 -> Int -> Int
                                                   -> IO CInt

--------------------------------------------------------------------------------
-- Signature Generation

foreign import ccall unsafe botan_pk_op_sign_create :: MBA## BotanStructT
                                                    -> BotanStructT
                                                    -> BA## Word8
                                                    -> Word32
                                                    -> IO CInt

foreign import ccall unsafe botan_pk_op_sign_output_length :: BotanStructT
                                                           -> MBA## CSize
                                                           -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_sign_update :: BotanStructT
                                                       -> BA## Word8 -> Int -> Int
                                                       -> IO CInt

foreign import ccall unsafe botan_pk_op_sign_finish :: BotanStructT
                                                    -> BotanStructT
                                                    -> MBA## Word8
                                                    -> MBA## CSize
                                                    -> IO CInt

foreign import ccall unsafe "&botan_pk_op_sign_destroy" botan_pk_op_sign_destroy :: FunPtr (BotanStructT -> IO ())

--------------------------------------------------------------------------------
-- Signature Verification

foreign import ccall unsafe botan_pk_op_verify_create :: MBA## BotanStructT
                                                      -> BotanStructT
                                                      -> BA## Word8
                                                      -> Word32
                                                      -> IO CInt

foreign import ccall unsafe "&botan_pk_op_verify_destroy" botan_pk_op_verify_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe hs_botan_pk_op_verify_update :: BotanStructT
                                                         -> BA## Word8 -> Int -> Int
                                                         -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_verify_finish :: BotanStructT
                                                         -> BA## Word8 -> Int -> Int
                                                         -> IO CInt

--------------------------------------------------------------------------------
-- Key Agreement

foreign import ccall unsafe botan_pk_op_key_agreement_create :: MBA## BotanStructT
                                                             -> BotanStructT
                                                             -> BA## Word8
                                                             -> Word32
                                                             -> IO CInt

foreign import ccall unsafe "&botan_pk_op_key_agreement_destroy" botan_pk_op_key_agreement_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_pk_op_key_agreement_export_public :: BotanStructT
                                                                    -> MBA## Word8 -> MBA## CSize
                                                                    -> IO CInt

foreign import ccall unsafe botan_pk_op_key_agreement_size :: BotanStructT
                                                           -> MBA## CSize
                                                           -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_key_agreement :: BotanStructT
                                                         -> Ptr Word8 -> CSize
                                                         -> BA## Word8 -> Int -> Int
                                                         -> BA## Word8 -> Int -> Int
                                                         -> IO CInt

{-
foreign import ccall unsafe hs_botan_mceies_encrypt :: BotanStructT -> BotanStructT
                                                    -> BA## Word8
                                                    -> BA## Word8 -> Int -> Int
                                                    -> BA## Word8 -> Int -> Int
                                                    -> MBA## Word8 -> MBA## CSize
                                                    -> IO CInt

foreign import ccall unsafe hs_botan_mceies_decrypt :: BotanStructT
                                                    -> BA## Word8
                                                    -> BA## Word8 -> Int -> Int
                                                    -> BA## Word8 -> Int -> Int
                                                    -> MBA## Word8 -> MBA## CSize
                                                    -> IO CInt
-}

--------------------------------------------------------------------------------
-- X.509 Certificates

-- | Certificate key usage constraints.
type KeyUsageConstraint = CUInt

pattern NO_CONSTRAINTS     :: KeyUsageConstraint
pattern DIGITAL_SIGNATURE  :: KeyUsageConstraint
pattern NON_REPUDIATION    :: KeyUsageConstraint
pattern KEY_ENCIPHERMENT   :: KeyUsageConstraint
pattern DATA_ENCIPHERMENT  :: KeyUsageConstraint
pattern KEY_AGREEMENT      :: KeyUsageConstraint
pattern KEY_CERT_SIGN      :: KeyUsageConstraint
pattern CRL_SIGN           :: KeyUsageConstraint
pattern ENCIPHER_ONLY      :: KeyUsageConstraint
pattern DECIPHER_ONLY      :: KeyUsageConstraint
pattern NO_CONSTRAINTS      = #const NO_CONSTRAINTS
pattern DIGITAL_SIGNATURE   = #const DIGITAL_SIGNATURE
pattern NON_REPUDIATION     = #const NON_REPUDIATION
pattern KEY_ENCIPHERMENT    = #const KEY_ENCIPHERMENT
pattern DATA_ENCIPHERMENT   = #const DATA_ENCIPHERMENT
pattern KEY_AGREEMENT       = #const KEY_AGREEMENT
pattern KEY_CERT_SIGN       = #const KEY_CERT_SIGN
pattern CRL_SIGN            = #const CRL_SIGN
pattern ENCIPHER_ONLY       = #const ENCIPHER_ONLY
pattern DECIPHER_ONLY       = #const DECIPHER_ONLY     

foreign import ccall unsafe "&botan_x509_cert_destroy" botan_x509_cert_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe hs_botan_x509_cert_load :: MBA## BotanStructT -- ^ botan_x509_cert_t* cert_obj
                                                    -> BA## Word8 -> Int -> Int
                                                    -> IO CInt

foreign import ccall unsafe botan_x509_cert_load_file :: MBA## BotanStructT
                                                      -> BA## Word8
                                                      -> IO CInt

foreign import ccall unsafe botan_x509_cert_dup :: MBA## BotanStructT
                                                -> BotanStructT
                                                -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_time_starts :: BotanStructT
                                                            -> MBA## Word8
                                                            -> MBA## Int
                                                            -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_time_expires :: BotanStructT
                                                             -> MBA## Word8
                                                             -> MBA## Int
                                                             -> IO CInt

foreign import ccall unsafe botan_x509_cert_not_before :: BotanStructT
                                                       -> MBA## Word64
                                                       -> IO CInt

foreign import ccall unsafe botan_x509_cert_not_after :: BotanStructT
                                                      -> MBA## Word64
                                                      -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_fingerprint :: BotanStructT
                                                            -> BA## Word8
                                                            -> MBA## Word8 -> MBA## Int
                                                            -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_serial_number :: BotanStructT
                                                              -> MBA## Word8
                                                              -> MBA## Int
                                                              -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_authority_key_id :: BotanStructT
                                                                 -> MBA## Word8 -> MBA## Int
                                                                 -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_subject_key_id :: BotanStructT -> MBA## Word8 -> MBA## Int -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_public_key_bits :: BotanStructT -> MBA## Word8 -> MBA## Int -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_public_key :: BotanStructT -> MBA## BotanStructT -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_issuer_dn :: BotanStructT -> BA## Word8 -> Int -> MBA## Word8 -> MBA## Int -> IO CInt

foreign import ccall unsafe botan_x509_cert_get_subject_dn :: BotanStructT
                                                           -> BA## Word8
                                                           -> Int
                                                           -> MBA## Word8 -> MBA## Int
                                                           -> IO CInt

foreign import ccall unsafe botan_x509_cert_to_string :: BotanStructT
                                                      -> MBA## Word8 -> MBA## Int
                                                      -> IO CInt

foreign import ccall unsafe botan_x509_cert_allowed_usage :: BotanStructT -> CUInt -> IO CInt

foreign import ccall unsafe hs_botan_x509_cert_verify :: BotanStructT
                                                      -> BA## BotanStructT -> Int 
                                                      -> BA## BotanStructT -> Int 
                                                      -> Int -> BA## Word8 -> Word64
                                                      -> IO CInt

foreign import ccall unsafe hs_botan_x509_cert_verify_with_crl :: BotanStructT
                                                               -> BA## BotanStructT -> Int 
                                                               -> BA## BotanStructT -> Int
                                                               -> BA## BotanStructT -> Int
                                                               -> Int -> BA## Word8 -> Word64
                                                               -> IO CInt

foreign import ccall unsafe hs_botan_x509_cert_verify_with_certstore_crl
    :: BotanStructT
    -> BA## BotanStructT -> Int 
    -> BotanStructT 
    -> BA## BotanStructT -> Int
    -> Int -> BA## Word8 -> Word64
    -> IO CInt

foreign import ccall unsafe botan_x509_cert_validation_status :: CInt -> IO CString

--------------------------------------------------------------------------------
-- X.509 Certificate Revocation Lists

foreign import ccall unsafe hs_botan_x509_crl_load :: MBA## BotanStructT
                                                   -> BA## Word8 -> Int -> Int
                                                   -> IO CInt

foreign import ccall unsafe botan_x509_crl_load_file :: MBA## BotanStructT -> BA## Word8 -> IO CInt

foreign import ccall unsafe "&botan_x509_crl_destroy" botan_x509_crl_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_x509_is_revoked :: BotanStructT -> BotanStructT -> IO CInt

--------------------------------------------------------------------------------
-- X.509 Certificate Store

foreign import ccall unsafe botan_x509_certstore_load_file :: MBA## BotanStructT -> BA## Word8 -> IO CInt

foreign import ccall unsafe botan_x509_certstore_load_system :: MBA## BotanStructT -> IO CInt

foreign import ccall unsafe "&botan_x509_certstore_destroy" botan_x509_certstore_destroy :: FunPtr (BotanStructT -> IO ())

--------------------------------------------------------------------------------
-- Advanced Encryption Standard (AES) Key Wrap Algorithm

foreign import ccall unsafe botan_key_wrap3394 :: Ptr Word8 -> CSize
                                                  -> Ptr Word8 -> CSize
                                                  -> MBA## Word8 -> MBA## CSize
                                                  -> IO CInt

foreign import ccall unsafe hs_botan_key_unwrap3394 :: BA## Word8 -> Int -> Int
                                                    -> Ptr Word8 -> CSize
                                                    -> Ptr Word8 -> CSize
                                                    -> IO CInt

--------------------------------------------------------------------------------
-- OTP

foreign import ccall unsafe hs_botan_hotp_init :: MBA## BotanStructT
                                               -> BA## Word8 -> Int -> Int
                                               -> BA## Word8
                                               -> Int
                                               -> IO CInt

foreign import ccall unsafe "&botan_hotp_destroy" botan_hotp_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_hotp_generate :: BotanStructT
                                                -> MBA## Word32
                                                -> Word64
                                                -> IO CInt

foreign import ccall unsafe botan_hotp_check :: BotanStructT
                                             -> MBA## Word64
                                             -> Word32
                                             -> Word64
                                             -> CSize
                                             -> IO CInt

foreign import ccall unsafe hs_botan_totp_init :: MBA## BotanStructT
                                               -> BA## Word8 -> Int -> Int
                                               -> BA## Word8
                                               -> Int -> Int
                                               -> IO CInt

foreign import ccall unsafe "&botan_totp_destroy" botan_totp_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_totp_generate :: BotanStructT
                                                -> MBA## Word32
                                                -> Word64
                                                -> IO CInt

foreign import ccall unsafe botan_totp_check :: BotanStructT
                                             -> Word32
                                             -> Word64
                                             -> CSize
                                             -> IO CInt

--------------------------------------------------------------------------------
-- Format Preserving Encryption

foreign import ccall unsafe hs_botan_fpe_fe1_init :: MBA## BotanStructT -> BotanStructT
                                                  -> BA## Word8 -> Int -> Int
                                                  -> Int -> Word32
                                                  -> IO CInt

foreign import ccall unsafe hs_botan_fpe_encrypt :: BotanStructT -> BotanStructT
                                                 -> BA## Word8 -> Int -> Int
                                                 -> IO CInt

foreign import ccall unsafe hs_botan_fpe_decrypt :: BotanStructT -> BotanStructT
                                                 -> BA## Word8 -> Int -> Int
                                                 -> IO CInt

foreign import ccall unsafe "&botan_fpe_destroy" botan_fpe_destroy :: FunPtr (BotanStructT -> IO ())
-}
