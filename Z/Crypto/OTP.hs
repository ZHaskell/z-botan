module Z.Crypto.OTP where

import           Data.Word
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

-- | Generate a HOTP code for the provided counter.
genHOTP :: HOTP   -- ^ the HOTP object
        -> Word64 -- ^ counter
        -> IO Word32
genHOTP (HOTP hotp) counter = do
    withBotanStruct hotp $ \ hotp' -> do
        (a,_) <- allocPrimUnsafe $ \ code ->
            botan_hotp_generate hotp' code counter
        return a

newtype TOTP = TOTP BotanStruct

newTOTP :: V.Bytes -> CBytes -> Int -> Int -> IO TOTP
newTOTP key hashAlgo digits timeStep = do
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withCBytesUnsafe hashAlgo $ \ hashAlgo' ->
            TOTP <$> newBotanStruct (\ hotp -> hs_botan_totp_init hotp key' keyOff keyLen hashAlgo' digits timeStep) botan_totp_destroy

-- | Generate a TOTP code for the provided timestamp.
genTOTP :: TOTP   -- ^ the TOTP object
        -> Word64 -- ^ the current local timestamp
        -> IO Word32
genTOTP (TOTP totp) timestamp = do
    withBotanStruct totp $ \ totp' -> do
        (a, _) <- allocPrimUnsafe $ \ code ->
            botan_totp_generate totp' code timestamp
        return a
