module Z.Crypto.OTP where

import           Z.Botan.FFI
import           Z.Data.CBytes
import qualified Z.Data.Vector as V
import           Z.Foreign

newtype HOTP = HOTP BotanStruct

newHOTP :: V.Bytes -> CBytes -> Int -> IO HOTP
newHOTP key hashAlgo digits = do
      withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withCBytesUnsafe hashAlgo $ \ hashAlgo' ->
          HOTP <$> newBotanStruct (\ hotp -> hs_botan_hotp_init hotp key' keyOff keyLen hashAlgo' digits) botan_hotp_destroy

newtype TOTP = TOTP BotanStruct

newTOTP :: V.Bytes -> CBytes -> Int -> Int -> IO TOTP
newTOTP key hashAlgo digits timeStep = do
      withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withCBytesUnsafe hashAlgo $ \ hashAlgo' ->
          TOTP <$> newBotanStruct (\ hotp -> hs_botan_totp_init hotp key' keyOff keyLen hashAlgo' digits timeStep) botan_totp_destroy
