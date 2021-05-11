{-|
Module      : Z.Crypto.RNG
Description : Random Number Generators
Copyright   : Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

Several different RNG types are implemented. Some access hardware RNGs, which are only available on certain platforms. Others are mostly useful in specific situations.

-}

module Z.Crypto.RNG
  ( -- * RNG
    RNGType(..), RNG
  , newRNG, getRNG, getRandom
  , reseedRNG, reseedRNGFromRNG, addEntropyRNG
  -- * Internal
  , withRNG
  ) where

import           Control.Monad
import           Data.IORef
import           GHC.Conc
import           GHC.Generics
import           System.IO.Unsafe
import           Z.Botan.Exception
import           Z.Botan.FFI
import qualified Z.Data.Array      as A
import           Z.Data.CBytes
import           Z.Data.JSON       (JSON)
import qualified Z.Data.Text       as T
import qualified Z.Data.Vector     as V
import           Z.Foreign

-- | RNG types.
data RNGType = SystemRNG | AutoSeededRNG | ProcessorRNG
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass (T.Print, JSON)

-- | Opaque botan RNG type.
newtype RNG = RNG BotanStruct
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Initialize a random number generator object from the given 'RNGType'
newRNG :: RNGType -> IO RNG
newRNG typ = RNG <$> newBotanStruct
    (\ bts -> withCBytesUnsafe (rngTypeCBytes typ) (botan_rng_init bts))
    botan_rng_destroy
  where
    rngTypeCBytes SystemRNG     = "system"
    rngTypeCBytes AutoSeededRNG = "user"
    rngTypeCBytes ProcessorRNG  = "hwrng"

-- | Use RNG as a `botan_rng_t` object.
withRNG :: RNG -> (BotanStructT -> IO a) -> IO a
withRNG (RNG rng) f = withBotanStruct rng f

-- | Get an autoseeded RNG from a global RNG pool divide by haskell capability.
--
-- Botan internal use a lock to protect user-space RNG, which may cause contention if shared.
-- This function will fetch an autoseeded RNG from a global RNG pool, which is recommended under
-- concurrent settings.
getRNG :: IO RNG
getRNG = do
    (cap, _) <- threadCapability =<< myThreadId
    rngArray <- readIORef rngArrayRef
    A.indexArrM rngArray (cap `rem` A.sizeofArr rngArray)
  where
    rngArrayRef :: IORef (A.SmallArray RNG)
    {-# NOINLINE rngArrayRef #-}
    rngArrayRef = unsafePerformIO $ do
        numCaps <- getNumCapabilities
        rngArray <- A.newArr numCaps
        forM_ [0..numCaps-1] $ \ i -> do
            A.writeArr rngArray i =<< newRNG AutoSeededRNG
        irngArray <- A.unsafeFreezeArr rngArray
        newIORef irngArray

-- | Get random bytes from a random number generator.
getRandom :: RNG -> Int -> IO V.Bytes
getRandom r siz =  withRNG r $ \ rng -> do
    (b, _) <- allocPrimVectorUnsafe siz $ \ buf ->
        throwBotanIfMinus_ (botan_rng_get rng buf (fromIntegral siz))
    return b

-- | Reseeds the random number generator with bits number of bits from the 'SystemRNG'.
reseedRNG :: RNG -> Int -> IO ()
reseedRNG r siz = withRNG r $ \ rng -> do
    throwBotanIfMinus_ (botan_rng_reseed rng (fromIntegral siz))

-- | Reseeds the random number generator with bits number of bits from the given source RNG.
reseedRNGFromRNG :: RNG -> RNG -> Int -> IO ()
reseedRNGFromRNG r1 r2 siz =
    withRNG r1 $ \ rng1 -> do
        withRNG r2 $ \ rng2 -> do
            throwBotanIfMinus_ (botan_rng_reseed_from_rng rng1 rng2 (fromIntegral siz))

-- | Adds the provided seed material to the internal RNG state.
--
-- This call may be ignored by certain RNG instances (such as 'ProcessorRNG' or, on some systems, the 'SystemRNG').
addEntropyRNG :: RNG -> V.Bytes -> IO ()
addEntropyRNG r seed =
    withRNG r $ \ rng -> do
        withPrimVectorUnsafe seed $ \ pseed offseed lseed -> do
            throwBotanIfMinus_ (hs_botan_rng_add_entropy rng pseed
                    (fromIntegral offseed) (fromIntegral lseed))
