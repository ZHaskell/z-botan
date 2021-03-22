module Z.Crypto.PubKey.ElGamal where

import Z.Botan.FFI
  ( botan_privkey_destroy,
    botan_privkey_load_elgamal,
    botan_pubkey_destroy,
    botan_pubkey_load_elgamal,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.MPI (MPI (..))
import Z.Crypto.PubKey.PubKey (PrivKey (..), PubKey (..))

newElGamalPriv :: MPI -> MPI -> MPI -> IO PrivKey
newElGamalPriv (MPI p) (MPI g) (MPI x) = do
  withBotanStruct p $ \p' ->
    withBotanStruct g $ \g' ->
      withBotanStruct x $ \x' ->
        PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_elgamal privKey p' g' x') botan_privkey_destroy

newElGamalPub :: MPI -> MPI -> MPI -> IO PubKey
newElGamalPub (MPI p) (MPI g) (MPI y) = do
  withBotanStruct p $ \p' ->
    withBotanStruct g $ \g' ->
      withBotanStruct y $ \y' ->
        PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_elgamal pubKey p' g' y') botan_pubkey_destroy
