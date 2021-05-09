module Z.Crypto.FPE where

import           Z.Botan.FFI
import           Z.Crypto.MPI
import qualified Z.Data.Vector as V
import           Z.Foreign

newtype FPE = FPE BotanStruct

newFPE :: MPI
       -> V.Bytes
       -> Int
       -> IO FPE
newFPE mpi key rounds = do
  withMPI mpi $ \ mpi' ->
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
      FPE <$> newBotanStruct (\ fpe ->
        hs_botan_fpe_fe1_init fpe mpi' key' keyOff keyLen rounds 1)
        botan_fpe_destroy
