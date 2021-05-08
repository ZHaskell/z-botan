module Z.Crypto.KeyWrap where

import           Z.Botan.Errno
import           Z.Botan.Exception
import           Z.Botan.FFI
import qualified Z.Data.ASCII      as C
import qualified Z.Data.Vector     as V
import           Z.Foreign

maxWrappedKeySiz :: Int
maxWrappedKeySiz = 128

keyWrap :: V.Bytes -- ^ key
        -> V.Bytes -- ^ kek
        -> IO V.Bytes
keyWrap key kek = do
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withPrimVectorUnsafe kek $ \ kek' kekOff kekLen -> do
            (a, _) <- allocPrimVectorUnsafe maxWrappedKeySiz $ \ wrap -> do
                (a', _) <- allocPrimUnsafe @Int $ \ siz ->
                    throwBotanIfMinus_ (hs_botan_key_wrap3394 key' keyOff keyLen kek' kekOff kekLen wrap siz)
                pure a'
            return a

