module Z.Crypto.PubKey.DSA where

import Z.Botan.FFI
  ( botan_privkey_destroy,
    botan_privkey_load_dsa,
    botan_pubkey_destroy,
    botan_pubkey_load_dsa,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.MPI (MPI (..))
import Z.Crypto.PubKey.PubKey (PrivKey (..), PubKey (..))

newDSAPriv :: MPI -> MPI -> MPI -> MPI -> IO PrivKey
newDSAPriv (MPI p) (MPI q) (MPI g) (MPI x) = do
  withBotanStruct p $ \p' ->
    withBotanStruct q $ \q' ->
      withBotanStruct g $ \g' ->
        withBotanStruct x $ \x' ->
          PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_dsa privKey p' q' g' x') botan_privkey_destroy

newDSAPub :: MPI -> MPI -> MPI -> MPI -> IO PubKey
newDSAPub (MPI p) (MPI q) (MPI g) (MPI y) = do
  withBotanStruct p $ \p' ->
    withBotanStruct q $ \q' ->
      withBotanStruct g $ \g' ->
        withBotanStruct y $ \y' ->
          PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_dsa pubKey p' q' g' y') botan_pubkey_destroy
