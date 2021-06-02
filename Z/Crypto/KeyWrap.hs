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
import           Z.Crypto.SafeMem
import qualified Z.Data.Vector as V
import           Z.Foreign

-- | Wrap the input key using kek (the key encryption key), and return the result. It will be 8 bytes longer than the input key.
keyWrap :: HasCallStack
        => Secret   -- ^ key
        -> Secret   -- ^ kek
        -> IO V.Bytes
{-# INLINABLE keyWrap #-}
keyWrap key kek =
    withSecret key $ \ key' keyLen ->
    withSecret kek $ \ kek' kekLen ->
    allocBotanBufferUnsafe (secretSize key + 8) $
        botan_key_wrap3394 key' keyLen kek' kekLen

-- | Unwrap a key wrapped with rfc3394_keywrap.
keyUnwrap :: HasCallStack
          => V.Bytes -- ^ wrapped key
          -> Secret -- ^ kek
          -> IO Secret
{-# INLINABLE keyUnwrap #-}
keyUnwrap key kek =
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
    withSecret kek $ \ kek' kekLen ->
    let out_len = V.length key - 8
    in newSecret out_len $ \ out ->
        hs_botan_key_unwrap3394 key' keyOff keyLen kek' kekLen out (fromIntegral out_len)
