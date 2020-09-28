{-# LANGUAGE CApiFFI #-}

module Z.Botan.FFI where

import Foreign.Ptr

#include "hs_botan.h"

botanVersionMajor :: Int
botanVersionMajor = #const BOTAN_VERSION_MAJOR


foreign import ccall unsafe "hs_botan.h new_tls_client" new_tls_client :: IO (Ptr a)
