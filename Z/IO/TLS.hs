{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MultiWayIf #-}

module Z.IO.TLS where

import Control.Monad
import Control.Concurrent
import Control.Monad.IO.Class
import GHC.Stack
import Z.Data.Vector as V
import Data.Word
import Z.Data.Text as T
import Z.Data.PrimRef.PrimIORef
import Z.IO.Exception
import Z.IO.Network
import Z.IO.Buffered
import Z.IO.Resource
import Z.IO.UV.Manager
import Z.Botan.FFI
import Z.Foreign
import Data.Bits
import Foreign.Ptr


data TLSClient = TLSClient
    { tlsTCPBufferedInput  :: BufferedInput UVStream
    , tlsTCPOutput         :: Ptr Word8 -> Int -> IO ()
    , tlsBotanClient       :: {-# UNPACK #-} !(Ptr BotanTLSClient)
    , tlsBotanCallbacks    :: {-# UNPACK #-} !(Ptr BotanCallbacks)
    , tlsClientRecvBuf     :: {-# UNPACK #-} !(Ptr Word8)
    , tlsClientEmitBuf     :: {-# UNPACK #-} !(Ptr Word8)
    }

data TLSClientConfig = TLSClientConfig
    { tlsClientTCPConfig :: TCPClientConfig
    , tlsClientServerInfo :: (V.Bytes, V.Bytes, Word32)
    }

defaultTLSClientConfig :: TLSClientConfig
defaultTLSClientConfig = TLSClientConfig defaultTCPClientConfig
                                         ("", "", 0)

instance Input TLSClient where
    readInput tlsc@TLSClient{..} readBuf readLen = do
        (rbuf_index, reading_index) <- peekTLSClientRecvIndex tlsBotanCallbacks
        if reading_index < rbuf_index
        then do
            let bufLen = rbuf_index - reading_index
            if readLen < bufLen
            then do
                copyPtr readBuf (tlsClientRecvBuf `plusPtr` reading_index) readLen
                pokeTLSClientRecvIndex tlsBotanCallbacks rbuf_index (reading_index + readLen)
                return readLen
            else do
                copyPtr readBuf (tlsClientRecvBuf `plusPtr` reading_index) bufLen
                pokeTLSClientRecvIndex tlsBotanCallbacks 0 0
                return bufLen
        else do
            record <- readTLSRecord tlsTCPBufferedInput
            if V.null record
            then return 0
            else do
                withPrimVectorSafe record $ \ p len ->
                    hs_tls_received_data tlsBotanClient p (fromIntegral len)
                -- during receiving, remote could initiate a re-handshake
                ebuf_index <- peekTLSClientEmitBufIndexAndReset tlsBotanCallbacks
                case ebuf_index of
                    FATAL_ALERT -> do
                        errmsg <- fromNullTerminated tlsClientEmitBuf
                        throwIO $ FatalAlert (T.validate errmsg) callStack
                    BOTAN_TLS_EXCEPTION -> do
                        errmsg <- fromNullTerminated tlsClientEmitBuf
                        throwIO $ TLSException (T.validate errmsg) callStack
                    _ -> when (ebuf_index > 0) (tlsTCPOutput tlsClientEmitBuf ebuf_index)
                -- go back and check record_received_buffer
                readInput tlsc readBuf readLen


instance Output TLSClient where
    writeOutput tlsc@TLSClient{..} p len = do
        hs_tls_send tlsBotanClient p (fromIntegral len)
        ebuf_index <- peekTLSClientEmitBufIndexAndReset tlsBotanCallbacks
        case ebuf_index of
            FATAL_ALERT -> do
                errmsg <- fromNullTerminated tlsClientEmitBuf
                throwIO $ FatalAlert (T.validate errmsg) callStack
            BOTAN_TLS_EXCEPTION -> do
                errmsg <- fromNullTerminated tlsClientEmitBuf
                throwIO $ TLSException (T.validate errmsg) callStack
            _ -> when (ebuf_index > 0) (tlsTCPOutput tlsClientEmitBuf ebuf_index)


initTLSClient :: HasCallStack => TLSClientConfig -> Resource TLSClient
initTLSClient TLSClientConfig{..} = do
    tcp <- initTCPClient tlsClientTCPConfig
    client <- initResource new_tls_client free_tls_client
    liftIO $ do
        (callbacks, rbuf, ebuf) <- peekBotanTLSClientBufs client
        tcpBufInp <- newBufferedInput' MAX_CIPHERTEXT_SIZE tcp
        let tcpOut = writeOutput tcp
        ebuf_index <- peekTLSClientEmitBufIndexAndReset callbacks
        handshake tcpBufInp tcpOut client callbacks rbuf ebuf ebuf_index
        return (TLSClient tcpBufInp tcpOut client callbacks rbuf ebuf)
  where
    handshake tcpBufInp tcpOut client callbacks rbuf ebuf ebuf_index = do
        when (ebuf_index > 0) (tcpOut ebuf ebuf_index)
        readTLSRecord tcpBufInp >>= \ record -> withPrimVectorSafe record $ \ p len ->
            hs_tls_received_data client p (fromIntegral len)
        ebuf_index' <- peekTLSClientEmitBufIndexAndReset callbacks
        case ebuf_index' of
            FATAL_ALERT -> do
                errmsg <- fromNullTerminated ebuf
                throwIO $ FatalAlert (T.validate errmsg) callStack
            BOTAN_TLS_EXCEPTION -> do
                errmsg <- fromNullTerminated ebuf
                throwIO $ TLSException (T.validate errmsg) callStack
            SESSION_ESTABLISHED -> return ()
            -- ^ continue handshake process
            _ -> handshake tcpBufInp tcpOut client callbacks rbuf ebuf ebuf_index'


--------------------------------------------------------------------------------


data TLSServerConfig = TLSServerConfig
    { tlsServerTCPConfig :: TCPServerConfig
    , tlsServerInfo :: (V.Bytes, V.Bytes, Word32)
    }

defaultTLSServerConfig :: TLSClientConfig
defaultTLSServerConfig = TLSClientConfig defaultTCPClientConfig
                                         ("", "", 0)

startTLSServer :: TLSServerConfig -> IO ()
startTLSServer = error "W.I.P"

--------------------------------------------------------------------------------

data TLSException = FatalAlert Text CallStack
                  | TLSException Text CallStack deriving Show
instance Exception TLSException

readTLSRecord :: Input i => BufferedInput i -> IO (V.Bytes)
readTLSRecord buf = do
    chunk <- readBuffer buf
    if V.length chunk < 5
    then if V.null chunk
        then return V.empty
        else throwIO (ShortReadException callStack)
    else do
        let sizeh = fromIntegral (chunk `V.index` 3)
            sizel = fromIntegral (chunk `V.index` 4)
            size = sizeh `unsafeShiftL` 8 + sizel
            rec_size = 5 + size
            chunk_size = V.length chunk
        if chunk_size < rec_size
        then do
            rest <- readExactly' (rec_size - chunk_size) buf
            let record = chunk `V.append` rest
            return $! record
        else do
            let (record, rest) = V.splitAt rec_size chunk
            unReadBuffer rest buf
            return $! record
