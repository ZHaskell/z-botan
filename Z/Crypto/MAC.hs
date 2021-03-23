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
import Z.Crypto.Hash ( hashTypeToCBytes, HashType, updateHash, hashChunks )
import Z.Data.CBytes as CB
    ( concat, fromText, withCBytesUnsafe, CBytes )
import qualified Z.Data.Text as T
import Z.Foreign
    ( allocPrimUnsafe, allocPrimVectorUnsafe, withPrimVectorUnsafe, indexPrimArray )
import qualified Z.Data.Vector as V
import Z.IO.BIO ( Sink, BIO(BIO) )
import System.IO.Unsafe ( unsafePerformIO )

data MACType = CMAC BlockCipherType
             | OMAC BlockCipherType
             | GMAC BlockCipherType
             | CBC_MAC BlockCipherType
             | HMAC HashType
             | Poly1305
             | SipHash Int Int
             | X9'19_MAC

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
}

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
mac :: HasCallStack => MACType -> V.Bytes ->V.Bytes
{-# INLINABLE mac #-}
mac mt inp = unsafePerformIO $ do
    m <- newMAC mt
    updateMAC m inp
    finalMAC m

-- | Directly compute a chunked message's mac.
macChunks :: HasCallStack => MACType -> [V.Bytes] -> V.Bytes
{-# INLINABLE macChunks #-}
macChunks mt inp = unsafePerformIO $ do
    m <- newMAC mt 
    mapM_ (updateMAC m) inp
    finalMAC m