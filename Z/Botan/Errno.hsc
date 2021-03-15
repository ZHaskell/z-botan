{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE CApiFFI #-}

module Z.Botan.Errno where

import Foreign.C.Types
import Z.Data.CBytes

#include "hs_botan.h"

-- | Generally returned to indicate success
pattern BOTAN_FFI_SUCCESS                         :: CInt
-- | Note this value is positive, but still represents an error condition. In indicates that the function completed successfully, but the value provided was not correct. For example botan_bcrypt_is_valid returns this value if the password did not match the hash.
pattern BOTAN_FFI_INVALID_VERIFIER                :: CInt
-- | The input was invalid. (Currently this error return is not used.)
pattern BOTAN_FFI_ERROR_INVALID_INPUT             :: CInt
-- | While decrypting in an AEAD mode, the tag failed to verify.
pattern BOTAN_FFI_ERROR_BAD_MAC                   :: CInt
-- | Functions which write a variable amount of space return this if the indicated buffer length was insufficient to write the data. In that case, the output length parameter is set to the size that is required.
pattern BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE :: CInt
-- | An exception was thrown while processing this request, but no further details are available.
pattern BOTAN_FFI_ERROR_EXCEPTION_THROWN          :: CInt
-- | Memory allocation failed
pattern BOTAN_FFI_ERROR_OUT_OF_MEMORY             :: CInt
-- | A value provided in a flag variable was unknown.
pattern BOTAN_FFI_ERROR_BAD_FLAG                  :: CInt
-- | A null pointer was provided as an argument where that is not allowed.
pattern BOTAN_FFI_ERROR_NULL_POINTER              :: CInt
-- | An argument did not match the function.
pattern BOTAN_FFI_ERROR_BAD_PARAMETER             :: CInt
-- | An object that requires a key normally must be keyed before use (eg before encrypting or MACing data). If this is not done, the operation will fail and return this error code.
pattern BOTAN_FFI_ERROR_KEY_NOT_SET               :: CInt
-- | An invalid key length was provided with a call to x_set_key.
pattern BOTAN_FFI_ERROR_INVALID_KEY_LENGTH        :: CInt
-- | This is returned if the functionality is not available for some reason. For example if you call botan_hash_init with a named hash function which is not enabled, this error is returned.
pattern BOTAN_FFI_ERROR_NOT_IMPLEMENTED           :: CInt
-- | This is used if an object provided did not match the function. For example calling botan_hash_destroy on a botan_rng_t object will cause this return.
pattern BOTAN_FFI_ERROR_INVALID_OBJECT            :: CInt
-- | Something bad happened, but we are not sure why or how.
pattern BOTAN_FFI_ERROR_UNKNOWN_ERROR             :: CInt
pattern BOTAN_FFI_SUCCESS                         = (#const BOTAN_FFI_SUCCESS)
pattern BOTAN_FFI_INVALID_VERIFIER                = (#const BOTAN_FFI_INVALID_VERIFIER)
pattern BOTAN_FFI_ERROR_INVALID_INPUT             = (#const BOTAN_FFI_ERROR_INVALID_INPUT)
pattern BOTAN_FFI_ERROR_BAD_MAC                   = (#const BOTAN_FFI_ERROR_BAD_MAC)
pattern BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE = (#const BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE)
pattern BOTAN_FFI_ERROR_EXCEPTION_THROWN          = (#const BOTAN_FFI_ERROR_EXCEPTION_THROWN)
pattern BOTAN_FFI_ERROR_OUT_OF_MEMORY             = (#const BOTAN_FFI_ERROR_OUT_OF_MEMORY)
pattern BOTAN_FFI_ERROR_BAD_FLAG                  = (#const BOTAN_FFI_ERROR_BAD_FLAG)
pattern BOTAN_FFI_ERROR_NULL_POINTER              = (#const BOTAN_FFI_ERROR_NULL_POINTER)
pattern BOTAN_FFI_ERROR_BAD_PARAMETER             = (#const BOTAN_FFI_ERROR_BAD_PARAMETER)
pattern BOTAN_FFI_ERROR_KEY_NOT_SET               = (#const BOTAN_FFI_ERROR_KEY_NOT_SET)
pattern BOTAN_FFI_ERROR_INVALID_KEY_LENGTH        = (#const BOTAN_FFI_ERROR_INVALID_KEY_LENGTH)
pattern BOTAN_FFI_ERROR_NOT_IMPLEMENTED           = (#const BOTAN_FFI_ERROR_NOT_IMPLEMENTED)
pattern BOTAN_FFI_ERROR_INVALID_OBJECT            = (#const BOTAN_FFI_ERROR_INVALID_OBJECT)
pattern BOTAN_FFI_ERROR_UNKNOWN_ERROR             = (#const BOTAN_FFI_ERROR_UNKNOWN_ERROR)
