module Z.Crypto.OTP where

import           Data.Word
import           Z.Botan.Errno
import           Z.Botan.FFI
import           Z.Data.CBytes
import qualified Z.Data.Vector as V
import           Z.Foreign

newtype HOTP = HOTP BotanStruct

data OTPAlgo =
        OTP_SHA_1
    |   OTP_SHA_256
    |   OTP_SHA_512

otpAlgoToBytes :: OTPAlgo -> CBytes
otpAlgoToBytes OTP_SHA_1   = "SHA-1"
otpAlgoToBytes OTP_SHA_256 = "SHA-256"
otpAlgoToBytes OTP_SHA_512 = "SHA-512"

data OTPDigit =
        OTP_DIGIT_6
    |   OTP_DIGIT_7
    |   OTP_DIGIT_8

otpDigitToInt :: OTPDigit -> Int
otpDigitToInt OTP_DIGIT_6 = 6
otpDigitToInt OTP_DIGIT_7 = 7
otpDigitToInt OTP_DIGIT_8 = 8

newHOTP :: V.Bytes -> OTPAlgo -> OTPDigit -> IO HOTP
newHOTP key otpAlgo digits = do
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withCBytesUnsafe (otpAlgoToBytes otpAlgo) $ \ hashAlgo' ->
            HOTP <$> newBotanStruct (\ hotp -> hs_botan_hotp_init hotp key' keyOff keyLen hashAlgo' (otpDigitToInt digits)) botan_hotp_destroy

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

newTOTP :: V.Bytes -> OTPAlgo -> OTPDigit -> Int -> IO TOTP
newTOTP key otpAlgo digits timeStep = do
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withCBytesUnsafe (otpAlgoToBytes otpAlgo) $ \ hashAlgo' ->
            TOTP <$> newBotanStruct (\ hotp -> hs_botan_totp_init hotp key' keyOff keyLen hashAlgo' (otpDigitToInt digits) timeStep) botan_totp_destroy

-- | Generate a TOTP code for the provided timestamp.
genTOTP :: TOTP   -- ^ the TOTP object
        -> Word64 -- ^ the current local timestamp
        -> IO Word32
genTOTP (TOTP totp) timestamp = do
    withBotanStruct totp $ \ totp' -> do
        (a, _) <- allocPrimUnsafe $ \ code ->
            botan_totp_generate totp' code timestamp
        return a

-- | Verify a TOTP code.
checkTOTP :: TOTP   -- ^ the TOTP object
          -> Word32 -- ^ the presented OTP
          -> Word64 -- ^ timestamp the current local timestamp
          -> Int    -- ^ specifies the acceptable amount
          -> IO Bool
checkTOTP (TOTP totp) code timestamp driftAmount = do
    withBotanStruct totp $ \ totp' -> do
        ret <- botan_totp_check totp' code timestamp driftAmount
        return $! ret == BOTAN_FFI_SUCCESS
