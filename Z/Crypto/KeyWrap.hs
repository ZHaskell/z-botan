module Z.Crypto.KeyWrap where

import           Z.Botan.FFI
import qualified Z.Data.Vector as V
import           Z.Foreign

maxWrappedKeySiz :: Int
maxWrappedKeySiz = 128

-- keyWrap :: V.Bytes -- ^ key
--         -> V.Bytes -- ^ kek
--         -> IO V.Bytes
-- keyWrap key kek = do
--     withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
--         withPrimVectorUnsafe kek $ \ kek' kekOff kekLen -> do
--             siz' <- newIORef 0
--             (a, _) <- allocPrimVectorUnsafe maxWrappedKeySiz $ \ wrap -> do
--                 (a', _) <- allocPrimUnsafe @Int $ \ siz ->
--                     throwBotanIfMinus_ (hs_botan_key_wrap3394 key' keyOff keyLen kek' kekOff kekLen wrap siz)
--                 writeIORef siz' a'
--             siz'' <- readIORef siz'
--             let a'' = V.take siz'' a
--             return a''

-- keyUnwrap :: V.Bytes -- ^ wrapped key
--           -> V.Bytes -- ^ kek
--           -> IO V.Bytes
-- keyUnwrap key kek = do
--     withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
--         withPrimVectorUnsafe kek $ \ kek' kekOff kekLen -> do
--             siz' <- newIORef 0
--             (a, _) <- allocPrimVectorUnsafe maxWrappedKeySiz $ \ wrap -> do
--                 (a', _) <- allocPrimUnsafe @Int $ \ siz ->
--                     throwBotanIfMinus_ (hs_botan_key_unwrap3394 key' keyOff keyLen kek' kekOff kekLen wrap siz)
--                 writeIORef siz' a'
--             siz'' <- readIORef siz'
--             let a'' = V.take siz'' a
--             return a''

keyWrap :: V.Bytes -- ^ key
        -> V.Bytes -- ^ kek
        -> IO V.Bytes
keyWrap key kek = do
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withPrimVectorUnsafe kek $ \ kek' kekOff kekLen ->
            allocBotanBufferUnsafe maxWrappedKeySiz $ \ ret retSiz ->
                hs_botan_key_wrap3394 key' keyOff keyLen kek' kekOff kekLen ret retSiz

keyUnwrap :: V.Bytes -- ^ wrapped key
          -> V.Bytes -- ^ kek
          -> IO V.Bytes
keyUnwrap key kek = do
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        withPrimVectorUnsafe kek $ \ kek' kekOff kekLen ->
            allocBotanBufferUnsafe maxWrappedKeySiz $ \ ret retSiz ->
                hs_botan_key_unwrap3394 key' keyOff keyLen kek' kekOff kekLen ret retSiz
