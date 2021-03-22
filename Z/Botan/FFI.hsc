module Z.Botan.FFI where

import           Data.Word
import           Foreign.Ptr
import           GHC.Generics
import           GHC.Types          (IO (..))
import           Z.IO.Exception
import           Z.Botan.Exception
import           Z.Data.CBytes
import           Z.Data.JSON         (JSON)
import qualified Z.Data.Vector      as V
import qualified Z.Data.Text        as T
import           Z.Foreign
import           Z.Foreign.CPtr

#include "hs_botan.h"

--------------------------------------------------------------------------------

foreign import ccall unsafe hs_botan_hex_encode :: BA## Word8 -> Int -> Int -> MBA## Word8 -> IO ()
foreign import ccall unsafe hs_botan_hex_encode_lower :: BA## Word8 -> Int -> Int -> MBA## Word8 -> IO ()
foreign import ccall unsafe hs_botan_hex_decode :: BA## Word8 -> Int -> Int -> MBA## Word8 -> IO ()

--------------------------------------------------------------------------------

-- | Internal type to representation botan struct, botan_xxx_t is always pointer type.

type BotanStruct = CPtr ()
type BotanStructT = Ptr ()

withBotanStruct :: BotanStruct -> (BotanStructT -> IO a) -> IO a
withBotanStruct = withCPtr

newBotanStruct :: HasCallStack
               => (MBA## BotanStructT -> IO CInt)   -- ^ init function
               -> FunPtr (BotanStructT -> IO a)    -- ^ destroy function pointer
               -> IO BotanStruct
newBotanStruct init_ destroy = do
    (bts, _) <- newCPtrUnsafe (\ pp -> throwBotanIfMinus_ (init_ pp)) destroy
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
    deriving anyclass (T.Print, JSON)

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
-- PBKDF

foreign import ccall unsafe hs_botan_pwdhash :: BA## Word8
                                             -> Int -> Int -> Int
                                             -> MBA## Word8 -> Int
                                             -> BA## Word8 -> Int -> Int
                                             -> BA## Word8 -> Int -> Int
                                             -> IO CInt

foreign import ccall unsafe hs_botan_pwdhash_timed :: BA## Word8
                                                   -> Int
                                                   -> MBA## Word8 -> Int
                                                   -> BA## Word8 -> Int -> Int
                                                   -> BA## Word8 -> Int -> Int
                                                   -> IO CInt

foreign import ccall safe "hs_botan_pwdhash_timed"
    hs_botan_pwdhash_timed_safe :: BA## Word8
                                -> Int
                                -> MBA## Word8 -> Int
                                -> BA## Word8 -> Int -> Int
                                -> BA## Word8 -> Int -> Int
                                -> IO CInt

--------------------------------------------------------------------------------
-- KDF

foreign import ccall unsafe hs_botan_kdf :: BA## Word8
                                         -> MBA## Word8 -> Int
                                         -> BA## Word8 -> Int -> Int
                                         -> BA## Word8 -> Int -> Int
                                         -> BA## Word8 -> Int -> Int
                                         -> IO CInt


---------------------------------------------------------------------------------
-- MAC

foreign import ccall unsafe botan_mac_init :: MBA## BotanStructT -> BA## Word8 -> Word32 -> IO CInt
foreign import ccall unsafe "&botan_mac_destroy" botan_mac_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_mac_output_length ::BotanStructT -> MBA## Word8 -> IO CInt

foreign import ccall unsafe hs_botan_mac_set_key :: BotanStructT -> BA## Word8 -> Int -> Int -> IO CInt

foreign import ccall unsafe hs_botan_mac_update :: BotanStructT -> BA## Word8 -> Int -> IO CInt

foreign import ccall unsafe hs_botan_mac_final :: BotanStructT -> BA## Word8 -> Int -> MBA## Word8 -> IO　CInt

foreign import ccall unsafe hs_botan_mac_clear :: BotanStructT -> IO CInt

foreign import ccall unsafe hs_botan_mac_name ::  BotanStructT -> MBA## Word8 -> MBA## Int -> IO CInt

foreign import ccall unsafe hs_botan_mac_get_keyspec :: BotanStructT -> MBA## Int -> MBA## Int -> MBA## Int -> IO CInt

--------------------------------------------------------------------------------
-- Public Key Creation, Import and Export (at Z.Crypto.PubKey)

foreign import ccall unsafe botan_privkey_create :: MBA## BotanStructT -- ^ botan_privkey_t* key
                                                 -> BA## Word8 -- ^ const char* algo_name
                                                 -> BA## Word8 -- ^ const char* algo_params
                                                 -> BotanStructT -- ^ botan_rng_t rng
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
-- Password Hashing

foreign import ccall unsafe botan_bcrypt_generate :: MBA## Word8 -> Int
                                                  -> BA## Word8
                                                  -> BotanStructT
                                                  -> Int
                                                  -> Word32
                                                  -> IO CInt

--------------------------------------------------------------------------------
-- RSA specific functions

foreign import ccall unsafe botan_privkey_rsa_get_p :: BotanStructT -- ^ botan_mp_t p
                                                    -> BotanStructT -- ^ botan_privkey_t rsa_key
                                                    -> IO CInt

foreign import ccall unsafe botan_privkey_rsa_get_q :: BotanStructT -- ^ botan_mp_t q
                                                    -> BotanStructT -- ^ botan_privkey_t rsa_key
                                                    -> IO CInt

foreign import ccall unsafe botan_privkey_rsa_get_d :: BotanStructT -- ^ botan_mp_t d
                                                    -> BotanStructT -- ^ botan_privkey_t rsa_key
                                                    -> IO CInt

foreign import ccall unsafe botan_privkey_rsa_get_n :: BotanStructT -- ^ botan_mp_t n
                                                    -> BotanStructT -- ^ botan_privkey_t rsa_key
                                                    -> IO CInt

foreign import ccall unsafe botan_privkey_rsa_get_e :: BotanStructT -- ^ botan_mp_t e
                                                    -> BotanStructT -- ^ botan_privkey_t rsa_key
                                                    -> IO CInt

foreign import ccall unsafe botan_pubkey_rsa_get_e :: BotanStructT -- ^ botan_mp_t e
                                                   -> BotanStructT -- ^ botan_pubkey_t rsa_key
                                                   -> IO CInt

foreign import ccall unsafe botan_pubkey_rsa_get_n :: BotanStructT -- ^ botan_mp_t n
                                                   -> BotanStructT -- ^ botan_pubkey_t rsa_key
                                                   -> IO CInt

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
                                                              -> Int
                                                              -> MBA## Int
                                                              -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_encrypt :: BotanStructT
                                                   -> BotanStructT
                                                   -> MBA## Word8 -> MBA## Int
                                                   -> BA## Word8 -> Int -> Int
                                                   -> IO CInt

foreign import ccall unsafe botan_pk_op_decrypt_create :: MBA## BotanStructT
                                                       -> BotanStructT
                                                       -> BA## Word8
                                                       -> Word32
                                                       -> IO CInt

foreign import ccall unsafe "&botan_pk_op_decrypt_destroy" botan_pk_op_decrypt_destroy :: FunPtr (BotanStructT -> IO ())

foreign import ccall unsafe botan_pk_op_decrypt_output_length :: BotanStructT
                                                              -> Int
                                                              -> MBA## Int
                                                              -> IO CInt

foreign import ccall unsafe hs_botan_pk_op_decrypt :: BotanStructT
                                                   -> MBA## Word8 -> MBA## Int
                                                   -> BA## Word8 -> Int -> Int
                                                   -> IO CInt

--------------------------------------------------------------------------------
-- Signature Generation

foreign import ccall unsafe "&botan_pk_op_sign_destroy" botan_pk_op_sign_destroy :: FunPtr (BotanStructT -> IO ())

--------------------------------------------------------------------------------
-- Signature Verification

foreign import ccall unsafe "&botan_pk_op_verify_destroy" botan_pk_op_verify_destroy :: FunPtr (BotanStructT -> IO ())

--------------------------------------------------------------------------------
-- Key Agreement

foreign import ccall unsafe "&botan_pk_op_key_agreement_destroy" botan_pk_op_key_agreement_destroy :: FunPtr (BotanStructT -> IO ())

