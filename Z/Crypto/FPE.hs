module Z.Crypto.FPE where

import           Z.Botan.FFI
import           Z.Crypto.MPI
import qualified Z.Data.Vector as V
import           Z.Foreign

newtype FPE = FPE BotanStruct

-- | Initialize an FPE operation to encrypt/decrypt integers less than n. It is
--   expected that n is trivially factorable into small integers. Common usage
--   would be n to be a power of 10.
newFPE :: MPI     -- ^ n
       -> V.Bytes -- ^ key
       -> IO FPE
newFPE mpi key = do
  withMPI mpi $ \ mpi' ->
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
      FPE <$> newBotanStruct (\ fpe ->
        hs_botan_fpe_fe1_init fpe mpi' key' keyOff keyLen 3 1)
        botan_fpe_destroy

encryptFPE :: FPE
           -> MPI
           -> V.Bytes
           -> IO CInt
encryptFPE (FPE fpe) mpi tweak = do
    withBotanStruct fpe $ \ fpe' ->
      withMPI mpi $ \ mpi' ->
        withPrimVectorUnsafe tweak $ \ tweak' tweakOff tweakLen ->
          hs_botan_fpe_encrypt fpe' mpi' tweak' tweakOff tweakLen

decryptFPE :: FPE
           -> MPI
           -> V.Bytes
           -> IO CInt
decryptFPE (FPE fpe) mpi tweak = do
    withBotanStruct fpe $ \ fpe' ->
      withMPI mpi $ \ mpi' ->
        withPrimVectorUnsafe tweak $ \ tweak' tweakOff tweakLen ->
          hs_botan_fpe_decrypt fpe' mpi' tweak' tweakOff tweakLen
