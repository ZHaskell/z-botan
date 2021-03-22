module Z.Crypto.PubKey where

import Data.Word
import Z.Botan.FFI
import Z.Crypto.PubKey.PubKey (PrivKey (..), PubKey (PubKey))
import Z.Crypto.RNG
import Z.Data.CBytes
import qualified Z.Data.Vector as V

newtype PKEncryption = PKEncryption BotanStruct

newPKEncryption :: PubKey -> CBytes -> IO PKEncryption
newPKEncryption (PubKey pubKey) padding = do
  withCBytesUnsafe padding $ \padding' ->
    withBotanStruct pubKey $ \pubKey' ->
      PKEncryption <$> newBotanStruct (\op -> botan_pk_op_encrypt_create op pubKey' padding' 0) botan_pk_op_encrypt_destroy

pkEncrypt :: PKEncryption -> RNG -> V.Bytes -> IO V.Bytes
pkEncrypt (PKEncryption op) (RNG rng) ptext = do
  withBotanStruct op $ \op' ->
    withBotanStruct rng $ \rng' -> undefined

newtype PKDecryption = PKDecryption BotanStruct

newPKDecryption :: PrivKey -> CBytes -> IO PKDecryption
newPKDecryption (PrivKey privKey) padding = do
  withCBytesUnsafe padding $ \padding' ->
    withBotanStruct privKey $ \privKey' ->
      PKDecryption <$> newBotanStruct (\op -> botan_pk_op_decrypt_create op privKey' padding' 0) botan_pk_op_decrypt_destroy
