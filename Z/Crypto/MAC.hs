module Z.Crypto.MAC where

import Z.Botan.Exception
import Z.Botan.FFI
import Z.Crypto.Cipher
import Z.Data.Text

data MACType = CMAC BlockCipherType
             | OMAC BlockCipherType
             | GMAC BlockCipherType
             | CBC_MAC BlockCipherType
             | HMAC HashType
             | Poly1305
             | Siphash Int Int
             | X9'19_MAC

mACTypeToCBytes :: MACType -> CBytes
mACTypeToCBytes (CMAC bc   ) = CB.concat ["CMAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (OMAC bc   ) = CB.concat ["OMAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (GMAC bc   ) = CB.concat ["GMAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (CBC_MAC bc) = CB.concat ["CBC-MAC(", blockCipherTypeToCBytes bc, ")"]
mACTypeToCBytes (HMAC ht)    = CB.concat ["HMAC(", hashTypeToCBytes ht, ")"]
mACTypeToCBytes Poly1305     = "Poly1305"
mACTypeToCBytes (Siphash r1 r2) = CB.concat ["CBC-MAC(", sizeCBytes r1, "," sizeCBytes r2, ")"]
  where
    sizeCBytes = CB.fromText . T.toText
mACTypeToCBytes X9'19_MAC = "X9.19-MAC"

data MAC = MAC {
    getMACStruct :: BotanStruct,
    getMACSiz :: Int
}

newMAC :: MACType -> IO MAC
