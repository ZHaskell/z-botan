module Z.Crypto.RSA where

import Z.Botan.FFI
  ( botan_privkey_destroy,
    botan_privkey_load_rsa,
    botan_privkey_rsa_get_d,
    botan_privkey_rsa_get_e,
    botan_privkey_rsa_get_n,
    botan_privkey_rsa_get_p,
    botan_privkey_rsa_get_q,
    botan_pubkey_destroy,
    botan_pubkey_load_rsa,
    botan_pubkey_rsa_get_e,
    botan_pubkey_rsa_get_n,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.MPI (MPI (..), unsafeNewMPI)
import Z.Crypto.PubKey (PrivKey (..), PubKey (..))

data RSAPrivArg = RSAPrivP | RSAPrivQ | RSAPrivD | RSAPrivN | RSAPrivE

getRSAPriv :: PrivKey -> RSAPrivArg -> MPI
getRSAPriv (PrivKey privKey) arg = unsafeNewMPI $ \mpi ->
  withBotanStruct privKey $ \privKey' ->
    ( case arg of
        RSAPrivP -> botan_privkey_rsa_get_p
        RSAPrivQ -> botan_privkey_rsa_get_q
        RSAPrivD -> botan_privkey_rsa_get_d
        RSAPrivN -> botan_privkey_rsa_get_n
        RSAPrivE -> botan_privkey_rsa_get_e
    )
      mpi
      privKey'

data RSAPubArg = RSAPubE | RSAPubN

getRSAPub :: PubKey -> RSAPubArg -> MPI
getRSAPub (PubKey pubKey) arg = unsafeNewMPI $ \mpi ->
  withBotanStruct pubKey $ \pubKey' ->
    ( case arg of
        RSAPubN -> botan_pubkey_rsa_get_n
        RSAPubE -> botan_pubkey_rsa_get_e
    )
      mpi
      pubKey'

-- | Initialize a private RSA key using arguments p, q, and e.
newRSAPriv :: MPI -> MPI -> MPI -> IO PrivKey
newRSAPriv (MPI p) (MPI q) (MPI e) = do
  withBotanStruct p $ \p' ->
    withBotanStruct q $ \q' ->
      withBotanStruct e $ \e' ->
        PrivKey <$> newBotanStruct (\privKey -> botan_privkey_load_rsa privKey p' q' e') botan_privkey_destroy

-- | Initialize a public RSA key using arguments n and e.
newRSAPub :: MPI -> MPI -> IO PubKey
newRSAPub (MPI n) (MPI e) = do
  withBotanStruct n $ \n' ->
    withBotanStruct e $ \e' ->
      PubKey <$> newBotanStruct (\pubKey -> botan_pubkey_load_rsa pubKey n' e') botan_pubkey_destroy
