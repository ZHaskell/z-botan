{-|
Module      : Z.Crypto.Cipher
Description : Block Cipher and Cipher modes
Copyright   : Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

This module provides raw block cipher and various cipher mode.

Block ciphers are a n-bit permutation for some small n, typically 64 or 128 bits. They are a cryptographic primitive used to generate higher level operations such as authenticated encryption.

A block cipher by itself, is only able to securely encrypt a single data block. To be able to securely encrypt data of arbitrary length, a mode of operation applies the block cipher’s single block operation repeatedly to encrypt an entire message.

-}
module Z.Crypto.Cipher
  ( -- * Block Cipher
    BlockCipherType(..), KeySpec(..)
  , BlockCipher, blockCipherName, blockCipherKeySpec, blockCipherSize
  , newBlockCipher, setBlockCipherKey, clearBlockCipher
  , encryptBlocks, decryptBlocks
    -- * Cipher Mode
  , CipherMode(..), CipherDirection(..)
  , Cipher, cipherName, cipherKeySpec, cipherTagLength, defaultNonceLength
  , newCipher, setCipherKey, clearCipher, runCipher
    -- * Stream Cipher
  , StreamCipherType(..), StreamCipher, streamCipherName, streamCipherKeySpec, defaultIVLength
  , newStreamCipher, setStreamCipherKey, clearStreamCipher
  , setStreamCipherIV, seekStreamCipher, runStreamCipher, streamCipherKeyStream, streamCipherBIO, keyStreamSource
    -- * Internal helps
  , blockCipherTypeToCBytes
  , withBlockCipher
  , withCipher
  , withStreamCipher
  ) where

import           Control.Monad
import           GHC.Generics
import           Z.Botan.Exception
import           Z.Botan.FFI
import           Z.Crypto.Hash
import           Z.Crypto.SafeMem
import           Z.Data.CBytes       as CB
import           Z.Data.JSON         (JSON)
import qualified Z.Data.Text         as T
import qualified Z.Data.Vector.Base  as V
import           Z.Foreign
import           Z.IO.BIO

-- | Available Block Ciphers
--
-- Botan includes a number of block ciphers that are specific to particular countries, as well as a few that are included mostly due to their use in specific protocols such as PGP but not widely used elsewhere. If you are developing new code and have no particular opinion, use AES-256. If you desire an alternative to AES, consider Serpent, SHACAL2 or Threefish.
--
-- Warning: Avoid any 64-bit block cipher in new designs. There are combinatoric issues that affect any 64-bit cipher that render it insecure when large amounts of data are processed.
--
data BlockCipherType
      -- | AES
      --
      -- Comes in three variants, AES-128, AES-192, and AES-256.
      -- The standard 128-bit block cipher. Many modern platforms offer hardware acceleration.
      -- However, on platforms without hardware support, AES implementations typically are vulnerable
      -- to side channel attacks.
      -- For x86 systems with SSSE3 but without AES-NI, Botan has an implementation which avoids known side channels.
    = AES128
    | AES192
    | AES256
      -- | ARIA
      --
      -- South Korean cipher used in industry there. No reason to use it otherwise.
    | ARIA128
    | ARIA192
    | ARIA256
      -- | Blowfish
      --
      -- A 64-bit cipher popular in the pre-AES era. Very slow key setup.
      -- Also used (with bcrypt) for password hashing.
    | Blowfish
      -- | Camellia
      --
      -- Comes in three variants, Camellia-128, Camellia-192, and Camellia-256.
      -- A Japanese design standardized by ISO, NESSIE and CRYPTREC. Rarely used outside of Japan.
    | Camellia128
    | Camellia192
    | Camellia256
      -- | Cascade
      --
      -- Creates a block cipher cascade, where each block is encrypted by two ciphers with independent keys.
      -- Useful if you're very paranoid. In practice any single good cipher (such as Serpent, SHACAL2, or AES-256)
      -- is more than sufficient.
      --
      -- Please set a key with size = max_key_size_A + max_key_size_B.
    | Cascade BlockCipherType BlockCipherType
      -- | CAST-128
      --
      -- A 64-bit cipher, commonly used in OpenPGP.
    | CAST128
      -- | CAST-256
      --
      -- A 128-bit cipher that was a contestant in the NIST AES competition.
      -- Almost never used in practice. Prefer AES or Serpent.
      -- Warning: Support for CAST-256 is deprecated and will be removed in a future major release.
    | CAST256
      -- | DES, 3DES, DESX
      --
      -- Originally designed by IBM and NSA in the 1970s. Today, DES's 56-bit key renders it insecure
      -- to any well-resourced attacker. DESX and 3DES extend the key length, and are still thought to be secure,
      -- modulo the limitation of a 64-bit block.
      -- All are somewhat common in some industries such as finance. Avoid in new code.
      -- Warning: Support for DESX is deprecated and it will be removed in a future major release.
    | DES
    | DESX
    | TripleDES
      -- | IDEA
      --
      -- An older but still unbroken 64-bit cipher with a 128-bit key.
      -- Somewhat common due to its use in PGP. Avoid in new designs.
    | IDEA
      -- | Kasumi
      --
      -- A 64-bit cipher used in 3GPP mobile phone protocols. There is no reason to use it outside of this context.
      -- Warning: Support for Kasumi is deprecated and will be removed in a future major release.
    | KASUMI
      -- | Lion
      --
      -- A "block cipher construction" which can encrypt blocks of nearly arbitrary length.
      -- Built from a stream cipher and a hash function.
      -- Useful in certain protocols where being able to encrypt large or arbitrary length blocks is necessary.
    | Lion HashType StreamCipherType Int
      -- | MISTY1
      --
      -- A 64-bit Japanese cipher standardized by NESSIE and ISO.
      -- Seemingly secure, but quite slow and saw little adoption. No reason to use it in new code.
      -- Warning: Support for MISTY1 is deprecated and will be removed in a future major release.
    | MISTY1
      -- | Noekeon
      --
      -- A fast 128-bit cipher by the designers of AES. Easily secured against side channels.
    | Noekeon
      -- | SEED
      --
      -- A older South Korean cipher, widely used in industry there. No reason to choose it otherwise.
    | SEED
      -- | Serpent
      --
      -- An AES contender. Widely considered the most conservative design.
      -- Fairly slow unless SIMD instructions are available.
    | Serpent
      -- | SHACAL2
      --
      -- The 256-bit block cipher used inside SHA-256. Accepts up to a 512-bit key.
      -- Fast, especially when SIMD or SHA-2 acceleration instructions are available.
      -- Standardized by NESSIE but otherwise obscure.
    | SHACAL2
      -- | Twofish
      --
      -- A 128-bit block cipher that was one of the AES finalists.
      -- Has a somewhat complicated key setup and a "kitchen sink" design.
    | Twofish
      -- | SM4
      --
      -- A 128-bit Chinese national cipher, required for use in certain commercial applications in China.
      -- Quite slow. Probably no reason to use it outside of legal requirements.
    | SM4
      -- | Threefish-512
      --
      -- A 512-bit tweakable block cipher that was used in the Skein hash function. Very fast on 64-bit processors.
    | Threefish512
      -- | XTEA
      --
      -- A 64-bit cipher popular for its simple implementation. Avoid in new code.
    | XTEA
  deriving (Show, Read, Eq, Ord, Generic)
  deriving anyclass (T.Print, JSON)

blockCipherTypeToCBytes :: BlockCipherType -> CBytes
{-# INLINABLE blockCipherTypeToCBytes #-}
blockCipherTypeToCBytes b = case b of
    AES128           ->    "AES-128"
    AES192           ->    "AES-192"
    AES256           ->    "AES-256"
    ARIA128          ->    "ARIA-128"
    ARIA192          ->    "ARIA-192"
    ARIA256          ->    "ARIA-256"
    Serpent          ->    "Serpent"
    SHACAL2          ->    "SHACAL2"
    Twofish          ->    "Twofish"
    Threefish512     ->    "Threefish-512"
    Blowfish         ->    "Blowfish"
    Camellia128      ->    "Camellia-128"
    Camellia192      ->    "Camellia-192"
    Camellia256      ->    "Camellia-256"
    DES              ->    "DES"
    DESX             ->    "DESX"
    TripleDES        ->    "TripleDES"
    Noekeon          ->    "Noekeon"
    CAST128          ->    "CAST-128"
    CAST256          ->    "CAST-256"
    IDEA             ->    "IDEA"
    KASUMI           ->    "KASUMI"
    MISTY1           ->    "MISTY1"
    SEED             ->    "SEED"
    SM4              ->    "SM4"
    XTEA             ->    "XTEA"
    Cascade b1 b2    ->    CB.concat [ "Cascade("
                                     , blockCipherTypeToCBytes b1
                                     , ","
                                     , blockCipherTypeToCBytes b2
                                     , ")"]
    Lion hasht st siz -> CB.concat [ "Lion("
                                  , hashTypeToCBytes hasht
                                  , ","
                                  , streamCipherTypeToCBytes st
                                  , ","
                                  , CB.fromText (T.toText siz)
                                  , ")"]

-- | A Botan block cipher.
--
-- In almost all cases, a bare block cipher is not what you should be using.
-- You probably want an authenticated cipher mode instead (see 'CipherMode'),
-- This interface is used to build higher level operations (such as cipher modes or MACs),
-- or in the very rare situation where ECB is required, eg for compatibility with an existing system.
--
data BlockCipher = BlockCipher
    { blockCipher        :: {-# UNPACK #-} !BotanStruct
    , blockCipherName    :: {-# UNPACK #-} !CBytes          -- ^ block cipher algo name
    , blockCipherSize    :: {-# UNPACK #-} !Int             -- ^ block cipher block size
    , blockCipherKeySpec :: {-# UNPACK #-} !KeySpec         -- ^ block cipher keyspec
    }
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Pass 'BlockCipher' to FFI as 'botan_block_cipher_t'.
withBlockCipher :: BlockCipher -> (BotanStructT -> IO r) -> IO r
{-# INLINABLE withBlockCipher #-}
withBlockCipher (BlockCipher bc _ _ _) = withBotanStruct bc

data KeySpec = KeySpec
    { keyLenMin :: {-# UNPACK #-} !Int  -- ^ minimum keylength
    , keyLenMax :: {-# UNPACK #-} !Int  -- ^ maximum keylength
    , keyLenMod :: {-# UNPACK #-} !Int  -- ^ keylength modulo
    }
    deriving (Eq, Ord, Show, Generic)
    deriving anyclass T.Print

-- | Create a new block cipher.
--
newBlockCipher :: HasCallStack => BlockCipherType -> IO BlockCipher
{-# INLINABLE newBlockCipher #-}
newBlockCipher typ = do
    let name = blockCipherTypeToCBytes typ
    bc <- newBotanStruct
        (\ bts -> withCBytesUnsafe name (botan_block_cipher_init bts))
        botan_block_cipher_destroy

    bsiz <- withBotanStruct bc botan_block_cipher_block_size

    (a, (b, (c, _))) <- withBotanStruct bc $ \ pbc ->
        allocPrimUnsafe $ \ pa ->
            allocPrimUnsafe $ \ pb ->
                allocPrimUnsafe $ \ pc ->
                    throwBotanIfMinus_
                        (botan_block_cipher_get_keyspec pbc pa pb pc)

    return (BlockCipher bc name (fromIntegral bsiz) (KeySpec a b c))

-- | Set the cipher key, which is required before encrypting or decrypting.
--
setBlockCipherKey :: HasCallStack => BlockCipher -> Secret -> IO ()
{-# INLINABLE setBlockCipherKey #-}
setBlockCipherKey (BlockCipher bc _ _ _) key =
    withBotanStruct bc $ \ pbc -> do
        withSecret key $ \ pkey key_len ->
            throwBotanIfMinus_ (botan_block_cipher_set_key pbc pkey key_len)

-- | Clear the internal state (such as keys) of this cipher object.
clearBlockCipher :: HasCallStack => BlockCipher -> IO ()
{-# INLINABLE clearBlockCipher #-}
clearBlockCipher (BlockCipher bc _ _ _) =
    withBotanStruct bc (throwBotanIfMinus_ . botan_block_cipher_clear)

-- | Encrypt blocks of data.
--
-- The key must have been set first with 'setBlockCipherKey'.
encryptBlocks :: HasCallStack
              => BlockCipher
              -> V.Bytes    -- ^ blocks of data, length must be equal to block_size * number_of_blocks
              -> Int        -- ^ number of blocks
              -> IO V.Bytes
{-# INLINABLE encryptBlocks #-}
encryptBlocks (BlockCipher bc _ blockSiz _) blocks n = do
    let inputLen = V.length blocks
    when (inputLen /= blockSiz * n) $
        throwBotanError BOTAN_FFI_ERROR_INVALID_INPUT
    withBotanStruct bc $ \ pbc -> do
        withPrimVectorUnsafe blocks $ \ pb pboff _ ->
            fst <$> allocPrimVectorUnsafe inputLen (\ pbuf ->
                throwBotanIfMinus_ (hs_botan_block_cipher_encrypt_blocks
                    pbc pb pboff pbuf n))

-- | Decrypt blocks of data.
--
-- The key must have been set first with 'setBlockCipherKey'.
decryptBlocks :: HasCallStack
              => BlockCipher
              -> V.Bytes    -- ^ blocks of data, length must be equal to block_size * number_of_blocks
              -> Int        -- ^ number of blocks
              -> IO V.Bytes
{-# INLINABLE decryptBlocks #-}
decryptBlocks (BlockCipher bc _ blockSiz _) blocks n = do
    let inputLen = V.length blocks
    when (inputLen /= blockSiz * n) $
        throwBotanError BOTAN_FFI_ERROR_INVALID_INPUT
    withBotanStruct bc $ \ pbc -> do
        withPrimVectorUnsafe blocks $ \ pb pboff _ ->
            fst <$> allocPrimVectorUnsafe inputLen (\ pbuf ->
                throwBotanIfMinus_ (hs_botan_block_cipher_decrypt_blocks
                    pbc pb pboff pbuf n))


--------------------------------------------------------------------------------
--

-- | All available cipher types.
--
-- A block cipher by itself, is only able to securely encrypt a single data block.
-- To be able to securely encrypt data of arbitrary length, a mode of operation applies
-- the block cipher’s single block operation repeatedly to encrypt an entire message.
--
-- Notes on the AEAD modes(CCM, ChaCha20Poly1305, EAX, GCM, OCB, SIV):
--
-- AEAD (Authenticated Encryption with Associated Data) modes provide message encryption,
-- message authentication, and the ability to authenticate additional data that is not included
-- in the ciphertext (such as a sequence number or header).
--
data CipherMode
    -- | ChaCha20Poly1305
    --
    -- Unlike the other AEADs which are based on block ciphers,
    -- this mode is based on the ChaCha stream cipher and the Poly1305 authentication code.
    -- It is very fast on all modern platforms.
    --
    -- ChaCha20Poly1305 supports 64-bit, 96-bit, and (since 2.8) 192-bit nonces.
    -- 64-bit nonces are the “classic” ChaCha20Poly1305 design.
    -- 96-bit nonces are used by the IETF standard version of ChaCha20Poly1305.
    -- And 192-bit nonces is the XChaCha20Poly1305 construction, which is somewhat less common.
    --
    -- For best interop use the IETF version with 96-bit nonces.
    -- However 96 bits is small enough that it can be dangerous to generate nonces randomly
    -- if more than ~ 2^32 messages are encrypted under a single key,
    -- since if a nonce is ever reused ChaCha20Poly1305 becomes insecure.
    -- It is better to use a counter for the nonce in this case.
    --
    -- If you are encrypting many messages under a single key and cannot maintain a counter for the nonce,
    -- prefer XChaCha20Poly1305 since a 192 bit nonce is large enough that randomly chosen nonces
    -- are extremely unlikely to repeat.
    = ChaCha20Poly1305
    -- | GCM
    --
    -- NIST standard, commonly used. Requires a 128-bit block cipher.
    -- Fairly slow, unless hardware support for carryless multiplies is available.
    | GCM BlockCipherType
    -- | OCB
    --
    -- A block cipher based AEAD. Supports 128-bit, 256-bit and 512-bit block ciphers.
    -- This mode is very fast and easily secured against side channels.
    -- Adoption has been poor because it is patented in the United States,
    -- though a license is available allowing it to be freely used by open source software.
    | OCB BlockCipherType
    -- | EAX
    -- A secure composition of CTR mode and CMAC. Supports 128-bit, 256-bit and 512-bit block ciphers.
    | EAX BlockCipherType
    -- | SIV
    --
    -- Requires a 128-bit block cipher. Unlike other AEADs, SIV is “misuse resistant”;
    -- if a nonce is repeated, SIV retains security, with the exception that if the same nonce
    -- is used to encrypt the same message multiple times,
    -- an attacker can detect the fact that the message was duplicated
    -- (this is simply because if both the nonce and the message are reused,
    -- SIV will output identical ciphertexts).
    | SIV BlockCipherType
    -- | CCM
    --
    -- A composition of CTR mode and CBC-MAC. Requires a 128-bit block cipher.
    -- This is a NIST standard mode, but that is about all to recommend it. Prefer EAX.
    | CCM BlockCipherType
    -- | CFB
    --
    -- CFB uses a block cipher to create a self-synchronizing stream cipher.
    -- It is used for example in the OpenPGP protocol. There is no reason to prefer it,
    -- as it has worse performance characteristics than modes such as CTR or CBC.
    | CFB BlockCipherType Int
    -- | XTS
    --
    -- XTS is a mode specialized for encrypting disk or database storage where ciphertext expansion
    -- is not possible. XTS requires all inputs be at least one full block (16 bytes for AES),
    -- however for any acceptable input length, there is no ciphertext expansion.
    | XTS BlockCipherType
    -- | CBC
    --
    -- CBC requires the plaintext be padded using a reversible rule. The following padding schemes are implemented
    --
    --  * PKCS#7 (RFC5652)
    --    The last byte in the padded block defines the padding length p,
    --    the remaining padding bytes are set to p as well.
    | CBC_PKCS7 BlockCipherType
    -- | CBC
    --
    --  * OneAndZeros (ISO/IEC 7816-4)
    --    The first padding byte is set to 0x80, the remaining padding bytes are set to 0x00.
    | CBC_OneAndZeros BlockCipherType
    -- | CBC
    --
    --  * ANSI X9.23
    --    The last byte in the padded block defines the padding length,
    --    the remaining padding is filled with 0x00.
    | CBC_X9'23 BlockCipherType
    -- | CBC
    --
    --  * ESP (RFC4303)
    --    Padding with 0x01, 0x02, 0x03...
    | CBC_ESP BlockCipherType
    -- | CTS
    --
    -- This scheme allows the ciphertext to have the same length as the plaintext,
    -- however using CTS requires the input be at least one full block plus one byte.
    -- It is also less commonly implemented.
    | CBC_CTS BlockCipherType
    -- | No padding CBC
    --
    -- Only use this mode when input length is a multipler of cipher block size.
    | CBC_NoPadding BlockCipherType
  deriving (Show, Read, Eq, Ord, Generic)
  deriving anyclass (T.Print, JSON)

cipherTypeToCBytes :: CipherMode -> CBytes
{-# INLINABLE cipherTypeToCBytes #-}
cipherTypeToCBytes ct = case ct of
    ChaCha20Poly1305 -> "ChaCha20Poly1305"
    GCM        bct -> blockCipherTypeToCBytes bct <> "/GCM"
    OCB        bct -> blockCipherTypeToCBytes bct <> "/OCB"
    EAX        bct -> blockCipherTypeToCBytes bct <> "/EAX"
    SIV        bct -> blockCipherTypeToCBytes bct <> "/SIV"
    CCM        bct -> blockCipherTypeToCBytes bct <> "/CCM"
    CFB           bct 0 -> blockCipherTypeToCBytes bct <> "/CFB"
    CFB           bct x -> CB.concat [ blockCipherTypeToCBytes bct
                                     , "/CFB("
                                     , CB.fromText (T.toText x)
                                     , ")"
                                     ]
    XTS             bct -> blockCipherTypeToCBytes bct <> "/XTS"
    CBC_PKCS7       bct -> blockCipherTypeToCBytes bct <> "/CBC/PKCS7"
    CBC_OneAndZeros bct -> blockCipherTypeToCBytes bct <> "/CBC/OneAndZeros"
    CBC_X9'23       bct -> blockCipherTypeToCBytes bct <> "/CBC/X9.23"
    CBC_ESP         bct -> blockCipherTypeToCBytes bct <> "/CBC/ESP"
    CBC_CTS         bct -> blockCipherTypeToCBytes bct <> "/CBC/CTS"
    CBC_NoPadding   bct -> blockCipherTypeToCBytes bct <> "/CBC/NoPadding"

-- | A Botan cipher.
data Cipher = Cipher
    { cipher                  :: {-# UNPACK #-} !BotanStruct
    , cipherName              :: {-# UNPACK #-} !CBytes        -- ^ cipher algo name
    , cipherKeySpec           :: {-# UNPACK #-} !KeySpec       -- ^ cipher keyspec
    , cipherTagLength         :: {-# UNPACK #-} !Int           -- ^ AEAD tag length, will be 0 for non-authenticated ciphers.
    , defaultNonceLength      :: {-# UNPACK #-} !Int    -- ^ a proper default nonce length.
    }
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Pass 'Cipher' to FFI as 'botan_cipher_t'.
withCipher :: Cipher -> (BotanStructT -> IO r) -> IO r
{-# INLINABLE withCipher #-}
withCipher (Cipher c _ _ _ _) = withBotanStruct c

-- | Create a new cipher.
--
newCipher :: HasCallStack => CipherMode -> CipherDirection -> IO Cipher
{-# INLINABLE newCipher #-}
newCipher typ dir = do
    let name = cipherTypeToCBytes typ
    ci <- newBotanStruct
        (\ bts -> withCBytesUnsafe name $ \ pb ->
            botan_cipher_init bts pb (cipherDirectionToFlag dir))
        botan_cipher_destroy

    withBotanStruct ci $ \ pci -> do

        (a, (b, (c, _))) <- allocPrimUnsafe $ \ pa ->
            allocPrimUnsafe $ \ pb ->
                allocPrimUnsafe $ \ pc ->
                    throwBotanIfMinus_
                        (botan_cipher_get_keyspec pci pa pb pc)

        (t, _) <- allocPrimUnsafe $ \ pt ->
            botan_cipher_get_tag_length pci pt

        (n, _) <- allocPrimUnsafe $ \ pn ->
            botan_cipher_get_default_nonce_length pci pn

        return (Cipher ci name (KeySpec a b c) t n)

-- | Clear the internal state (such as keys) of this cipher object.
--
clearCipher :: HasCallStack => Cipher -> IO ()
{-# INLINABLE clearCipher #-}
clearCipher ci = withCipher ci (throwBotanIfMinus_ . botan_cipher_clear)

-- | Set the key for this cipher object
--
setCipherKey :: HasCallStack => Cipher -> Secret -> IO ()
{-# INLINABLE setCipherKey #-}
setCipherKey ci key =
    withCipher ci $ \ pci -> do
        withSecret key $ \ pkey key_len -> do
            throwBotanIfMinus_ (botan_cipher_set_key pci pkey key_len)

-- | Do the encryption or decryption.
runCipher :: HasCallStack
          => Cipher
          -> Nonce         -- ^ nonce
          -> V.Bytes       -- ^ input
          -> V.Bytes       -- ^ associated data, ignored if not an AEAD
          -> IO V.Bytes
{-# INLINABLE runCipher #-}
runCipher ci nonce inp ad =
    withCipher ci $ \ pci -> do
        withPrimVectorUnsafe nonce $ \ pnonce nonce_off nonce_len ->
            throwBotanIfMinus_ (hs_botan_cipher_start pci pnonce nonce_off nonce_len)

        when (cipherTagLength ci /= 0) . withPrimVectorUnsafe ad $ \ pad ad_off ad_len -> do
            throwBotanIfMinus_ (hs_botan_cipher_set_associated_data
                pci pad ad_off ad_len)

        osiz <- hs_botan_cipher_output_size pci (V.length inp)
        (out, _) <- allocPrimVectorUnsafe osiz $ \ out ->
            withPrimVectorUnsafe inp $ \ pinp inp_off inp_len ->
                throwBotanIfMinus_ (hs_botan_cipher_finish pci out osiz pinp inp_off inp_len)
        return out

--------------------------------------------------------------------------------

-- | In contrast to block ciphers, stream ciphers operate on a plaintext stream instead of blocks. Thus encrypting data results in changing the internal state of the cipher and encryption of plaintext with arbitrary length is possible in one go (in byte amounts).
data StreamCipherType
      -- | A cipher mode that converts a block cipher into a stream cipher.
      --  It offers parallel execution and can seek within the output stream, both useful properties.
    = CTR_BE BlockCipherType
      -- | Another stream cipher based on a block cipher.
      -- Unlike CTR mode, it does not allow parallel execution or seeking within the output stream. Prefer CTR.
    | OFB BlockCipherType
      -- | A very fast cipher, now widely deployed in TLS as part of the ChaCha20Poly1305 AEAD.
      -- Can be used with 8 (fast but dangerous), 12 (balance), or 20 rounds (conservative).
      -- Even with 20 rounds, ChaCha is very fast. Use 20 rounds.
    | ChaCha8
    | ChaCha12
    | ChaCha20
      -- | An earlier iteration of the ChaCha design,
      -- this cipher is popular due to its use in the libsodium library. Prefer ChaCha.
    | Salsa20
      -- | This is the SHAKE-128 XOF exposed as a stream cipher.
      -- It is slower than ChaCha and somewhat obscure.
      -- It does not support IVs or seeking within the cipher stream.
    | SHAKE128'
      -- | An old and very widely deployed stream cipher notable for its simplicity.
      -- It does not support IVs or seeking within the cipher stream.
      -- Warning: RC4 is now badly broken. Avoid in new code and use only if
      -- required for compatibility with existing systems.
    | RC4
  deriving (Show, Read, Eq, Ord, Generic)
  deriving anyclass (T.Print, JSON)

-- | A Botan stream cipher.
data StreamCipher = StreamCipher
    { streamCipher                  :: {-# UNPACK #-} !BotanStruct
    , streamCipherName              :: {-# UNPACK #-} !CBytes        -- ^ cipher algo name
    , streamCipherKeySpec           :: {-# UNPACK #-} !KeySpec       -- ^ cipher keyspec
    , defaultIVLength               :: {-# UNPACK #-} !Int           -- ^ a proper default IV length.
    }

withStreamCipher :: StreamCipher -> (BotanStructT -> IO r) -> IO r
{-# INLINE withStreamCipher #-}
withStreamCipher (StreamCipher sci _ _ _) = withBotanStruct sci

streamCipherTypeToCBytes :: StreamCipherType -> CBytes
{-# INLINABLE streamCipherTypeToCBytes #-}
streamCipherTypeToCBytes s = case s of
    CTR_BE b  -> CB.concat ["CTR-BE(", blockCipherTypeToCBytes b, ")"]
    OFB b     -> CB.concat ["OFB(", blockCipherTypeToCBytes b, ")"]
    ChaCha8   -> "ChaCha(8)"
    ChaCha12  -> "ChaCha(12)"
    ChaCha20  -> "ChaCha(20)"
    Salsa20   -> "Salsa20"
    SHAKE128' ->  "SHAKE-128"
    RC4       -> "RC4"

-- | Create a new stream cipher.
--
newStreamCipher :: HasCallStack => StreamCipherType -> CipherDirection -> IO StreamCipher
{-# INLINABLE newStreamCipher #-}
newStreamCipher typ dir = do
    let name = streamCipherTypeToCBytes typ
    ci <- newBotanStruct
        (\ bts -> withCBytesUnsafe name $ \ pb ->
            botan_stream_cipher_init bts pb (cipherDirectionToFlag dir))
        botan_stream_cipher_destroy

    withBotanStruct ci $ \ pci -> do

        (a, (b, (c, _))) <- allocPrimUnsafe $ \ pa ->
            allocPrimUnsafe $ \ pb ->
                allocPrimUnsafe $ \ pc ->
                    throwBotanIfMinus_
                        (botan_stream_cipher_get_keyspec pci pa pb pc)

        (n, _) <- allocPrimUnsafe $ \ pn ->
            botan_stream_cipher_get_default_iv_length pci pn

        return (StreamCipher ci name (KeySpec a b c) n)

-- | Set the key for this cipher object
--
setStreamCipherKey :: HasCallStack => StreamCipher -> Secret -> IO ()
{-# INLINABLE setStreamCipherKey #-}
setStreamCipherKey ci key =
    withStreamCipher ci $ \ pci ->
    withSecret key $ \ pkey key_len ->
        throwBotanIfMinus_ (botan_stream_cipher_set_key pci pkey key_len)

-- | Set the initail vector for a 'StreamCipher'.
setStreamCipherIV :: StreamCipher -> Nonce -> IO ()
{-# INLINABLE setStreamCipherIV #-}
setStreamCipherIV sc nonce =
    withStreamCipher sc $ \ psc ->
    withPrimVectorUnsafe nonce $ \ n noff nlen ->
        throwBotanIfMinus_ $ hs_botan_stream_cipher_set_iv psc n noff nlen

-- | Clear the internal state (such as keys) of this cipher object.
--
clearStreamCipher :: HasCallStack => StreamCipher -> IO ()
{-# INLINABLE clearStreamCipher #-}
clearStreamCipher ci = withStreamCipher ci (throwBotanIfMinus_ . botan_stream_cipher_clear)

-- | Seek 'StreamCipher' 's state to given offset.
seekStreamCipher :: StreamCipher -> Int -> IO ()
{-# INLINABLE seekStreamCipher #-}
seekStreamCipher sc off =
    withStreamCipher sc $ \ psc ->
        throwBotanIfMinus_ $ botan_stream_cipher_seek psc (fromIntegral off)

-- | Update cipher with some data.
--
-- If the input size is not a multiplier of 'cipherUpdateGranularity', there'll
-- be some trailing input.
runStreamCipher :: HasCallStack
                   => StreamCipher
                   -> V.Bytes
                   -> IO V.Bytes        -- ^ trailing input, output
{-# INLINABLE runStreamCipher #-}
runStreamCipher sci input =
    withStreamCipher sci $ \ pci -> do
        withPrimVectorUnsafe input $ \ in_p in_off in_len -> do
            (out, _) <- allocPrimVectorUnsafe in_len $ \ out_p ->
                throwBotanIfMinus (hs_botan_stream_cipher_cipher pci
                    out_p in_p in_off in_len)
            return out

-- | Finish cipher with some data.
--
-- You can directly call this function to encrypt a whole message,
-- Note some cipher modes have a minimal input length requirement for last chunk(CTS, XTS, etc.).
streamCipherKeyStream :: HasCallStack
                      => StreamCipher
                      -> Int
                      -> IO V.Bytes
{-# INLINABLE streamCipherKeyStream #-}
streamCipherKeyStream sci siz =
    withStreamCipher sci $ \ pci -> do
        (pa, _) <- allocPrimVectorUnsafe siz $ \ out_p -> do
            throwBotanIfMinus (botan_stream_cipher_write_keystream pci out_p (fromIntegral siz))
        return pa

-- | Wrap a cipher into a 'BIO' node(experimental).
--
-- The cipher should have already started by setting key, nounce, etc,
-- for example to encrypt a file in constant memory:
--
-- @
-- import Z.Data.CBytes (CBytes)
-- import Z.IO.BIO
-- import Z.IO
-- import Z.Crypto.Cipher
--
-- encryptFile :: CBytes -> CBytes -> IO ()
-- encryptFile origin target = do
--     let demoKey = "12345678123456781234567812345678"
--         iv = "demo only, use random nonce"
--     cipher <- newStreamCipher (CTR_BE AES256) CipherEncrypt
--     setStreamCipherKey cipher demoKey
--     startCipher cipher nonce
--     encryptor <- cipherBIO cipher
--
--     withResource (initSourceFromFile origin) $ \\ src ->
--         withResource (initSinkToFile target) $ \\ sink ->
--             runBIO_ $ src . encryptor . sink
-- @
--
-- Note that many cipher modes have a maximum length limit on the plaintext under a security context,
-- i.e. a key nonce combination. If you want to encrypt a large message, please consider divide it into
-- smaller chunks, and re-key or change the iv.
streamCipherBIO :: HasCallStack => StreamCipher -> BIO V.Bytes V.Bytes
{-# INLINABLE streamCipherBIO #-}
streamCipherBIO c = \ k mbs -> case mbs of
    Just chunk -> k . Just =<< runStreamCipher c chunk
    _ -> k EOF

-- | Turn a 'StreamCipher' into a source, with each chunk size equal to 'defaultIVLength'.
--
keyStreamSource :: HasCallStack => StreamCipher -> Source V.Bytes
{-# INLINABLE keyStreamSource #-}
keyStreamSource c = \ k _ -> k . Just =<< streamCipherKeyStream c (defaultIVLength c)
