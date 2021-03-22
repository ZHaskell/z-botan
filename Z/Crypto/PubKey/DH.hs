module Z.Crypto.PubKey.DH where

import Z.Botan.FFI
  ( botan_privkey_destroy,
    botan_privkey_load_dh,
    botan_pubkey_destroy,
    botan_pubkey_load_dh,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.MPI (MPI (..))
import Z.Crypto.PubKey.PubKey (PrivKey (..), PubKey (..))

newDHPriv :: MPI -> MPI -> MPI -> IO PrivKey
newDHPriv (MPI p) (MPI g) (MPI x) = do
  withBotanStruct p $ \p' ->
    withBotanStruct g $ \g' ->
      withBotanStruct x $ \x' ->
        PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_dh privKey p' g' x') botan_privkey_destroy

newDHPub :: MPI -> MPI -> MPI -> IO PubKey
newDHPub (MPI p) (MPI g) (MPI y) = do
  withBotanStruct p $ \p' ->
    withBotanStruct g $ \g' ->
      withBotanStruct y $ \y' ->
        PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_dh pubKey p' g' y') botan_pubkey_destroy
