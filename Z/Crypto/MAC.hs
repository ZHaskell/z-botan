module Z.Crypto.MAC where

import Z.Botan.Exception ( HasCallStack, throwBotanIfMinus_ )
import Z.Botan.FFI
    ( BotanStruct,
      hs_botan_mac_clear,
      hs_botan_mac_update,
      hs_botan_mac_set_key,
      botan_mac_output_length,
      botan_mac_destroy,
      botan_mac_init,
      botan_hash_final,
      withBotanStruct,
      newBotanStruct )
import Z.Crypto.Cipher ( blockCipherTypeToCBytes, BlockCipherType )
import Z.Crypto.Hash (HashType, hashTypeToCBytes)
import Z.Data.CBytes as CB
    ( concat, fromText, withCBytesUnsafe, CBytes )
import qualified Z.Data.Text as T
import Z.Foreign
    ( allocPrimUnsafe, allocPrimVectorUnsafe, withPrimVectorUnsafe)
import qualified Z.Data.Vector as V
import Z.IO.BIO ( Sink, BIO(BIO) )
import System.IO.Unsafe ( unsafePerformIO )

data MACType = CMAC BlockCipherType
                -- ^ A modern CBC-MAC variant that avoids the security problems of plain CBC-MAC. 
                -- Approved by NIST. Also sometimes called OMAC.
             | OMAC BlockCipherType
               -- ^ 
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

mACTypeToCBytes :: MACType -> CBytes
mACTypeToCBytes (CMAC bc   ) = CB.concat ["CMAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (OMAC bc   ) = CB.concat ["OMAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (GMAC bc   ) = CB.concat ["GMAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (CBC_MAC bc) = CB.concat ["CBC-MAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (HMAC ht)    = CB.concat ["HMAC(", hashTypeToCBytes ht, ")"]
mACTypeToCBytes Poly1305     = "Poly1305"
mACTypeToCBytes (SipHash r1 r2) = CB.concat ["SipHash(", sizeCBytes r1, ",", sizeCBytes r2, ")"]
  where
    sizeCBytes = CB.fromText . T.toText
mACTypeToCBytes X9'19_MAC = "X9.19-MAC"

data MAC = MAC {
    getMACStruct :: BotanStruct,
    getMACName :: CBytes,
    getMACSiz :: Int
}deriving (Show, Eq)

newMAC :: MACType -> IO MAC
newMAC typ = do
    let name = mACTypeToCBytes typ
    bs <- newBotanStruct
        (\ bts -> withCBytesUnsafe name $ \ pt ->
            (botan_mac_init bts pt 0))
        botan_mac_destroy
    (osiz, _) <- withBotanStruct bs $ \ pbs ->
        allocPrimUnsafe $ \ pl ->
            botan_mac_output_length pbs pl
    return (MAC bs name osiz)

updateMAC :: HasCallStack => MAC -> V.Bytes -> IO ()
updateMAC (MAC bts _ _) bs = 
    withBotanStruct bts $ \ pbts ->
        withPrimVectorUnsafe bs $ \ pbs off len ->
            throwBotanIfMinus_ (hs_botan_mac_update pbts pbs off len)

setKeyMAC :: HasCallStack => MAC -> V.Bytes -> IO () 
setKeyMAC (MAC bts _ _) bs = 
    withBotanStruct bts $ \pbts->
        withPrimVectorUnsafe bs $ \pbs off len ->
            throwBotanIfMinus_ (hs_botan_mac_set_key pbts pbs off len)

finalMAC :: HasCallStack => MAC ->IO V.Bytes
{-# INLINABLE finalMAC #-}
finalMAC (MAC bts _ siz) = 
    withBotanStruct bts $ \ pbts -> do
        fst <$> allocPrimVectorUnsafe siz (\ pout ->
            throwBotanIfMinus_ (botan_hash_final pbts pout))

clearMAC :: HasCallStack => MAC -> IO ()
clearMAC (MAC bts _ _) = 
    throwBotanIfMinus_ (withBotanStruct bts hs_botan_mac_clear)

sinkToMAC :: HasCallStack => MAC -> Sink V.Bytes
sinkToMAC m = BIO push_ pull_
  where
    push_ x = updateMAC m x >> return Nothing
    pull_ = return Nothing

-- | Directly compute a message's mac 
mac :: HasCallStack => MACType -> V.Bytes -> V.Bytes ->V.Bytes
{-# INLINABLE mac #-}
mac mt inp key = unsafePerformIO $ do
    m <- newMAC mt
    setKeyMAC m key
    updateMAC m inp
    finalMAC m

-- | Directly compute a chunked message's mac.
macChunks :: HasCallStack => MACType -> [V.Bytes] -> V.Bytes
{-# INLINABLE macChunks #-}
macChunks mt inp = unsafePerformIO $ do
    m <- newMAC mt 
    mapM_ (updateMAC m) inp
    finalMAC m
