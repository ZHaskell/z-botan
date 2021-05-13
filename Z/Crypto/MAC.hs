{-|
Module      : Z.Crypto.MAC
Description : Message Authentication Codes (MAC)
Copyright   : YouShi, Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

A Message Authentication Code algorithm computes a tag over a message utilizing a shared secret key. Thus a valid tag confirms the authenticity and integrity of the message. Only entities in possession of the shared secret key are able to verify the tag.

-}

module Z.Crypto.MAC (
    -- * MAC type
    MACType(..)
  , MAC, macName, macSize
    -- * IUF interface
  , newMAC
  , setKeyMAC
  , updateMAC
  , finalMAC
  , clearMAC
  -- * function interface
  , mac, macChunks
  -- * BIO interface
  , sinkToMAC
  -- * Internal helper
  , macTypeToCBytes
  , withMAC
  ) where

import           GHC.Generics
import           System.IO.Unsafe  (unsafePerformIO)
import           Z.Botan.Exception
import           Z.Botan.FFI
import           Z.Crypto.Cipher   (BlockCipherType, blockCipherTypeToCBytes)
import           Z.Crypto.Hash     (HashType, hashTypeToCBytes)
import           Z.Data.CBytes     as CB
import qualified Z.Data.Text       as T
import qualified Z.Data.Vector     as V
import           Z.Foreign
import           Z.IO.BIO


data MACType = CMAC BlockCipherType
                -- ^ A modern CBC-MAC variant that avoids the security problems of plain CBC-MAC.
                -- Approved by NIST. Also sometimes called OMAC.
             | GMAC BlockCipherType
               -- ^ GMAC is related to the GCM authenticated cipher mode.
               -- It is quite slow unless hardware support for carryless multiplications is available.
               --  A new nonce must be used with each message authenticated, or otherwise all security is lost.
             | CBC_MAC BlockCipherType
              -- ^ An older authentication code based on a block cipher.
              -- Serious security problems,
              -- in particular insecure if messages of several different lengths are authenticated.
              --  Avoid unless required for compatibility.
             | HMAC HashType
              -- ^ A message authentication code based on a hash function. Very commonly used.
             | Poly1305
             -- ^ A polynomial mac (similar to GMAC). Very fast, but tricky to use safely.
             -- Forms part of the ChaCha20Poly1305 AEAD mode.
             -- A new key must be used for each message, or all security is lost.
             | SipHash Int Int
             -- ^ A modern and very fast PRF. Produces only a 64-bit output.
             -- Defaults to “SipHash(2,4)” which is the recommended configuration,
             -- using 2 rounds for each input block and 4 rounds for finalization.
             | X9'19_MAC
             -- ^ A CBC-MAC variant sometimes used in finance. Always uses DES.
             -- Sometimes called the “DES retail MAC”, also standardized in ISO 9797-1.
             -- It is slow and has known attacks. Avoid unless required.

macTypeToCBytes :: MACType -> CBytes
macTypeToCBytes (CMAC bc   ) = CB.concat ["CMAC(", blockCipherTypeToCBytes bc, ")"]
macTypeToCBytes (GMAC bc   ) = CB.concat ["GMAC(", blockCipherTypeToCBytes bc, ")"]
macTypeToCBytes (CBC_MAC bc) = CB.concat ["CBC-MAC(", blockCipherTypeToCBytes bc, ")"]
macTypeToCBytes (HMAC ht)    = CB.concat ["HMAC(", hashTypeToCBytes ht, ")"]
macTypeToCBytes Poly1305     = "Poly1305"
macTypeToCBytes (SipHash r1 r2) = CB.concat ["SipHash(", sizeCBytes r1, ",", sizeCBytes r2, ")"]
  where
    sizeCBytes = CB.fromText . T.toText
macTypeToCBytes X9'19_MAC = "X9.19-MAC"

data MAC = MAC
    { macStruct :: {-# UNPACK #-} !BotanStruct
    , macName   :: {-# UNPACK #-} !CBytes             -- ^ mac algo name
    , macSize   :: {-# UNPACK #-} !Int                -- ^ mac output size in bytes
    }
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Pass MAC to FFI as 'botan_mac_t'.
withMAC :: MAC -> (BotanStructT -> IO r) -> IO r
{-# INLINABLE withMAC #-}
withMAC (MAC m _ _) = withBotanStruct m

-- | Create a new 'MAC' object.
newMAC :: HasCallStack => MACType -> IO MAC
{-# INLINABLE newMAC #-}
newMAC typ = do
    let name = macTypeToCBytes typ
    bs <- newBotanStruct
        (\ bts -> withCBytesUnsafe name $ \ pt ->
            (botan_mac_init bts pt 0))
        botan_mac_destroy
    (osiz, _) <- withBotanStruct bs $ \ pbs ->
        allocPrimUnsafe @CSize $ \ pl ->
            botan_mac_output_length pbs pl
    return (MAC bs name (fromIntegral osiz))

-- | Set the random key.
setKeyMAC :: HasCallStack => MAC -> V.Bytes -> IO ()
{-# INLINABLE setKeyMAC #-}
setKeyMAC (MAC bts _ _) bs =
    withBotanStruct bts $ \pbts->
        withPrimVectorUnsafe bs $ \pbs off len ->
            throwBotanIfMinus_ (hs_botan_mac_set_key pbts pbs off len)

-- | Feed a chunk of input into a 'MAC' object.
updateMAC :: HasCallStack => MAC -> V.Bytes -> IO ()
{-# INLINABLE updateMAC #-}
updateMAC (MAC bts _ _) bs =
    withBotanStruct bts $ \ pbts ->
        withPrimVectorUnsafe bs $ \ pbs off len ->
            throwBotanIfMinus_ (hs_botan_mac_update pbts pbs off len)

finalMAC :: HasCallStack => MAC -> IO V.Bytes
{-# INLINABLE finalMAC #-}
finalMAC (MAC bts _ siz) =
    withBotanStruct bts $ \ pbts -> do
        fst <$> allocPrimVectorUnsafe siz (\ pout ->
            throwBotanIfMinus_ (botan_mac_final pbts pout))

-- | Reset the state of MAC object back to clean, as if no input has been supplied.
clearMAC :: HasCallStack => MAC -> IO ()
{-# INLINABLE clearMAC #-}
clearMAC (MAC bts _ _) =
    throwBotanIfMinus_ (withBotanStruct bts hs_botan_mac_clear)

-- | Trun 'MAC' to a 'V.Bytes' sink, update 'MAC' by write bytes to the sink.
--
sinkToMAC :: HasCallStack => MAC -> Sink V.Bytes
{-# INLINABLE sinkToMAC #-}
sinkToMAC h = \ k mbs -> case mbs of
    Just bs -> updateMAC h bs
    _       -> k EOF

-- | Directly compute a message's mac
mac :: HasCallStack => MACType
                    -> V.Bytes  -- ^ key
                    -> V.Bytes  -- ^ input
                    -> V.Bytes
{-# INLINABLE mac #-}
mac mt key inp = unsafePerformIO $ do
    m <- newMAC mt
    setKeyMAC m key
    updateMAC m inp
    finalMAC m

-- | Directly compute a chunked message's mac.
macChunks :: HasCallStack => MACType -> V.Bytes -> [V.Bytes] -> V.Bytes
{-# INLINABLE macChunks #-}
macChunks mt key inps = unsafePerformIO $ do
    m <- newMAC mt
    setKeyMAC m key
    mapM_ (updateMAC m) inps
    finalMAC m
