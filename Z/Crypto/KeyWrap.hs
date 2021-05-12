{-|
Module      : Z.Crypto.KeyWrap
Description : AES Key Wrapping
Copyright   : AnJie Dong, Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

This module provides RFC3394 key Wrapping. It uses a 128-bit, 192-bit, or 256-bit key to encrypt an input key. AES is always used. The input must be a multiple of 8 bytes; if not an exception is thrown.

-}
module Z.Crypto.KeyWrap where

import           Z.Botan.Exception
import           Z.Botan.FFI
import qualified Z.Data.Vector as V
import           Z.Foreign

-- | Wrap the input key using kek (the key encryption key), and return the result. It will be 8 bytes longer than the input key.
keyWrap :: HasCallStack
        => V.Bytes -- ^ key
        -> V.Bytes -- ^ kek
        -> IO V.Bytes
{-# INLINABLE keyWrap #-}
keyWrap key kek =
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
    withPrimVectorUnsafe kek $ \ kek' kekOff kekLen ->
    allocBotanBufferUnsafe (V.length key + 8) $
        hs_botan_key_wrap3394 key' keyOff keyLen kek' kekOff kekLen

-- | Unwrap a key wrapped with rfc3394_keywrap.
keyUnwrap :: HasCallStack
          => V.Bytes -- ^ wrapped key
          -> V.Bytes -- ^ kek
          -> IO V.Bytes
{-# INLINABLE keyUnwrap #-}
keyUnwrap key kek =
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
    withPrimVectorUnsafe kek $ \ kek' kekOff kekLen ->
    allocBotanBufferUnsafe (V.length key - 8) $
        hs_botan_key_unwrap3394 key' keyOff keyLen kek' kekOff kekLen
