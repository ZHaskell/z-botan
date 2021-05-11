{-|
Module      : Z.Botan.Exception
Description : Errno provided by botan
Copyright   : (c) Dong Han, 2020 - 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

Provides botan exception hierarchy.

-}

module Z.Botan.Exception (
  -- * Botan exceptions
    SomeBotanException(..)
  , botanExceptionToException
  , botanExceptionFromException
  -- * Concrete botan exception types
  , InvalidVerifier(..)
  , InvalidInput(..)
  , BadMac(..)
  , InsufficientBufferSpace(..)
  , ExceptionThrown(..)
  , OutOfMemory(..)
  , BadFlag(..)
  , NullPointer(..)
  , BadParameter(..)
  , KeyNotSet(..)
  , InvalidKeyLength(..)
  , NotImplemented(..)
  , InvalidObject(..)
  , UnknownError(..)
  -- * Throw botan exceptions
  , throwBotanIfMinus
  , throwBotanIfMinus_
  , throwBotanError
  -- * re-export
  , module Z.Botan.Errno
  , module Z.IO.Exception
 ) where

import Control.Monad
import Foreign.C.Types
import Data.Typeable
import Z.Botan.Errno
import Z.IO.Exception

-- | The root type of all botan exceptions, you can catch all botan exception by catching this root type.
--
data SomeBotanException = forall e . Exception e => SomeBotanException e

instance Show SomeBotanException where
    show (SomeBotanException e) = show e

instance Exception SomeBotanException

botanExceptionToException :: Exception e => e -> SomeException
botanExceptionToException = toException . SomeBotanException

botanExceptionFromException :: Exception e => SomeException -> Maybe e
botanExceptionFromException x = do
    SomeBotanException a <- fromException x
    cast a

#define BotanE(e) data e = e CInt CallStack deriving Show;  \
           instance Exception e where                     \
               { toException = botanExceptionToException     \
               ; fromException = botanExceptionFromException \
               }

BotanE(InvalidVerifier)
BotanE(InvalidInput)
BotanE(BadMac)
BotanE(InsufficientBufferSpace)
BotanE(ExceptionThrown)
BotanE(OutOfMemory)
BotanE(BadFlag)
BotanE(NullPointer)
BotanE(BadParameter)
BotanE(KeyNotSet)
BotanE(InvalidKeyLength)
BotanE(NotImplemented)
BotanE(InvalidObject)
BotanE(UnknownError)


throwBotanIfMinus :: (HasCallStack, Integral a) => IO a -> IO a
throwBotanIfMinus f = do
    r <- f
    when (r < 0) (throwBotanError_ (fromIntegral r) callStack)
    return r

throwBotanIfMinus_ :: (HasCallStack, Integral a) => IO a -> IO ()
throwBotanIfMinus_ f = do
    r <- f
    when (r < 0) (throwBotanError_ (fromIntegral r) callStack)

throwBotanError :: HasCallStack => CInt -> IO x
throwBotanError r = throwBotanError_ r callStack

throwBotanError_ :: CInt -> CallStack -> IO x
throwBotanError_ r cs =  case r of
    BOTAN_FFI_ERROR_INVALID_INPUT             -> throwIO (InvalidInput r cs)
    BOTAN_FFI_ERROR_BAD_MAC                   -> throwIO (BadMac r cs)
    BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE -> throwIO (InsufficientBufferSpace r cs)
    BOTAN_FFI_ERROR_EXCEPTION_THROWN          -> throwIO (ExceptionThrown r cs)
    BOTAN_FFI_ERROR_OUT_OF_MEMORY             -> throwIO (OutOfMemory r cs)
    BOTAN_FFI_ERROR_BAD_FLAG                  -> throwIO (BadFlag r cs)
    BOTAN_FFI_ERROR_NULL_POINTER              -> throwIO (NullPointer r cs)
    BOTAN_FFI_ERROR_BAD_PARAMETER             -> throwIO (BadParameter r cs)
    BOTAN_FFI_ERROR_KEY_NOT_SET               -> throwIO (KeyNotSet r cs)
    BOTAN_FFI_ERROR_INVALID_KEY_LENGTH        -> throwIO (InvalidKeyLength r cs)
    BOTAN_FFI_ERROR_NOT_IMPLEMENTED           -> throwIO (NotImplemented r cs)
    BOTAN_FFI_ERROR_INVALID_OBJECT            -> throwIO (InvalidObject r cs)
    _                                         -> throwIO (UnknownError r cs)
