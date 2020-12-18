module Z.Crypto.RNG
  ( -- * RNG
    RNGType(..), RNG
  , newRNG, getRandom
  , reseedRNG, reseedRNGFromRNG, addEntropyRNG
  ) where

import           Data.Word
import           Foreign.ForeignPtr
import           Foreign.Ptr
import           GHC.Generics
import           GHC.Prim           (mkWeak##)
import           GHC.Types          (IO (..))
import           Z.Botan.Exception
import           Z.Botan.Exception
import           Z.Data.CBytes
import           Z.Data.FFI
import           Z.Data.JSON         (EncodeJSON, ToValue, FromValue)
import qualified Z.Data.Vector      as V
import qualified Z.Data.Text.ShowT  as T
import           Z.Foreign
import           Z.Type.Utils

-- | RNG types.
data RNGType = SystemRNG | AutoSeededRNG | ProcessorRNG
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (T.ShowT, EncodeJSON, ToValue, FromValue)

-- | Opaque botan RNG type.
newtype RNG = RNG BotanStruct
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass T.ShowT

-- | Initialize a random number generator object from the given 'RNGType'
newRNG :: RNGType -> IO RNG
newRNG typ = RNG <$> newBotanStruct
    (\ bts -> withCBytesUnsafe (rngTypeCBytes typ) (botan_rng_init bts))
    botan_rng_destroy
  where
    rngTypeCBytes SystemRNG = "system"
    rngTypeCBytes AutoSeededRNG = "user"
    rngTypeCBytes ProcessorRNG = "hwrng"

-- | Get random bytes from a random number generator.
getRandom :: RNG -> Int -> IO V.Bytes
getRandom (RNG bs) siz = withBotanStruct bs $ \ rng -> do
    (b, _) <- allocPrimVectorUnsafe siz $ \ buf ->
        throwBotanIfMinus_ (botan_rng_get rng buf (fromIntegral siz))
    return b

-- | Reseeds the random number generator with bits number of bits from the 'SystemRNG'.
reseedRNG :: RNG -> Int -> IO ()
reseedRNG (RNG bs) siz = withBotanStruct bs $ \ rng -> do
    throwBotanIfMinus_ (botan_rng_reseed rng (fromIntegral siz))

-- | Reseeds the random number generator with bits number of bits from the given source RNG.
reseedRNGFromRNG :: RNG -> RNG -> Int -> IO ()
reseedRNGFromRNG (RNG bs1) (RNG bs2) siz =
    withBotanStruct bs1 $ \ rng1 -> do
        withBotanStruct bs2 $ \ rng2 -> do
            throwBotanIfMinus_ (botan_rng_reseed_from_rng rng1 rng2 (fromIntegral siz))

-- | Adds the provided seed material to the internal RNG state.
--
-- This call may be ignored by certain RNG instances (such as 'ProcessorRNG' or, on some systems, the 'SystemRNG').
addEntropyRNG :: RNG -> V.Bytes -> IO ()
addEntropyRNG (RNG bs) seed =
    withBotanStruct bs $ \ rng -> do
        withPrimVectorUnsafe seed $ \ pseed offseed lseed -> do
            throwBotanIfMinus_ (hs_botan_rng_add_entropy rng pseed
                    (fromIntegral offseed) (fromIntegral lseed))
