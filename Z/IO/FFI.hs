{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE CApiFFI #-}


module Z.Botan.FFI where

import Foreign.Ptr
import Foreign.Storable
import Foreign.C.Types
import Data.Word
import Z.Data.CBytes
import Z.IO

#include "hs_botan.h"

pattern BOTAN_VERSION_MAJOR :: Int
pattern BOTAN_VERSION_MAJOR = #const BOTAN_VERSION_MAJOR

pattern MAX_CIPHERTEXT_SIZE :: Int
pattern MAX_CIPHERTEXT_SIZE = #const HS_MAX_CIPHERTEXT_SIZE

pattern SESSION_ESTABLISHED :: Int
pattern SESSION_ESTABLISHED = #const HS_SESSION_ESTABLISHED

pattern FATAL_ALERT :: Int
pattern FATAL_ALERT = #const HS_FATAL_ALERT

pattern BOTAN_TLS_EXCEPTION :: Int
pattern BOTAN_TLS_EXCEPTION = #const HS_BOTAN_TLS_EXCEPTION

data BotanTLSClient
data BotanCallbacks

foreign import ccall unsafe "hs_botan.h new_tls_client" new_tls_client :: IO (Ptr BotanTLSClient)
foreign import ccall unsafe "hs_botan.h free_tls_client" free_tls_client :: Ptr BotanTLSClient -> IO ()
foreign import ccall unsafe "hs_botan.h hs_tls_received_data"
    hs_tls_received_data :: Ptr BotanTLSClient -> Ptr Word8 -> CSize -> IO ()
foreign import ccall unsafe "hs_botan.h hs_tls_send"
    hs_tls_send :: Ptr BotanTLSClient -> Ptr Word8 -> CSize -> IO ()

peekBotanTLSClientBufs :: Ptr BotanTLSClient -> IO (Ptr BotanCallbacks, Ptr Word8, Ptr Word8)
peekBotanTLSClientBufs p = do
    callbacks <- (#peek botan_tls_client_t, callbacks) p
    r <- (#peek botan_callbacks_t, record_received_buffer) callbacks
    e <- (#peek botan_callbacks_t, emit_data_buffer) callbacks
    return (callbacks, r, e)

peekTLSClientRecvIndex :: Ptr BotanCallbacks -> IO (Int, Int)
peekTLSClientRecvIndex callbacks = do
    r <- (#peek botan_callbacks_t, record_buffer_index) callbacks
    r' <- (#peek botan_callbacks_t, record_buffer_reading_index) callbacks
    return (r, r')

pokeTLSClientRecvIndex :: Ptr BotanCallbacks -> Int -> Int -> IO ()
pokeTLSClientRecvIndex callbacks r r' = do
    (#poke botan_callbacks_t, record_buffer_index) callbacks r
    (#poke botan_callbacks_t, record_buffer_reading_index) callbacks r'

peekTLSClientEmitBufIndexAndReset :: Ptr BotanCallbacks -> IO Int
peekTLSClientEmitBufIndexAndReset callbacks = do
    e <- (#peek botan_callbacks_t, emit_buffer_index) callbacks
    (#poke botan_callbacks_t, emit_buffer_index) callbacks (0 :: Int)
    return e

--------------------------------------------------------------------------------

data ServerInfo = ServerInfo
    { serverHostName :: HostName
    , serverServiceName :: ServiceName
    , serverPortNumber :: PortNumber
    }

initServerInfo :: ServerInfo -> Resource (Ptr ServerInfo)
initServerInfo =

--------------------------------------------------------------------------------

foreign import ccall unsafe "hs_botan.h new_certificate_store"
    new_credentials_t :: BA# Word8 -> BAAray# Word8 -> BA# Word8 -> IO (Ptr Credential)
foreign import ccall unsafe "hs_botan.h free_certificate_store"
    free_credentials_t :: Ptr Credential -> IO ()

data Credential = Credential
    { credentialCertKeyPair :: ([CBytes], CBytes)
    , credentialCAStore     :: CAStore
    } deriving (Show, Eq, Ord, Generic)

data CAStore
    = SystemCAStore
    | MozillaCAStore
    | CustomCAStore CBytes

initCredential :: Credential -> Resource (Ptr Credential)
initCredential (Credential (SystemCAStore path)) =
    initResource (new_certificate_store_system)
                 (free_certificate_store_system)
initCertificateStore (MozillaCAStore path) =
    initResource (new_certificate_store_system)
                 (free_certificate_store_system)
initCertificateStore (CustomCAStore path) =
    initResource (withCBytes path new_certificate_store)
                 (free_certificate_store)
