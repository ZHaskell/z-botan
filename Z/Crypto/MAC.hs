module Z.Crypto.MAC where

import Z.Botan.Exception
import Z.Botan.FFI
import Z.Crypto.Cipher
import Z.Data.Text

data MACType = CMAC
             | GMAC
             | CBC_MAC
             | Poly1305
             | Siphash
             | X919_MAC


data MAC = MAC {
    botanStruct :: BotanStruct,
    mac_type :: String,
    flags :: Int 
}

