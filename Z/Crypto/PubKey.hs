module Z.Crypto.PubKey where

import Z.Botan.Exception (throwBotanIfMinus_)
import Z.Botan.FFI
  ( BotanStruct,
    botan_pk_op_decrypt_create,
    botan_pk_op_decrypt_destroy,
    botan_pk_op_decrypt_output_length,
    botan_pk_op_encrypt_create,
    botan_pk_op_encrypt_destroy,
    botan_pk_op_encrypt_output_length,
    hs_botan_pk_op_decrypt,
    hs_botan_pk_op_encrypt,
    newBotanStruct,
    withBotanStruct,
  )
import Z.Crypto.PubKey.PubKey (PrivKey (..), PubKey (PubKey))
import Z.Crypto.RNG (RNG (..))
import Z.Data.CBytes (CBytes, withCBytesUnsafe)
import qualified Z.Data.Vector as V
import Z.Foreign
  ( allocPrimUnsafe,
    allocPrimVectorUnsafe,
    withPrimVectorUnsafe,
  )

newtype PKEncryption = PKEncryption BotanStruct

newPKEncryption :: PubKey -> CBytes -> IO PKEncryption
newPKEncryption (PubKey pubKey) padding = do
  withCBytesUnsafe padding $ \padding' ->
    withBotanStruct pubKey $ \pubKey' ->
      PKEncryption <$> newBotanStruct (\op -> botan_pk_op_encrypt_create op pubKey' padding' 0) botan_pk_op_encrypt_destroy

pkEncryptLen :: PKEncryption -> Int -> IO Int
pkEncryptLen (PKEncryption op) len = do
  withBotanStruct op $ \op' -> do
    (a, _) <- allocPrimUnsafe $ \ret -> throwBotanIfMinus_ (botan_pk_op_encrypt_output_length op' len ret)
    return a

pkEncrypt :: PKEncryption -> RNG -> V.Bytes -> IO V.Bytes
pkEncrypt enop@(PKEncryption op) (RNG rng) ptext = do
  withBotanStruct op $ \op' ->
    withBotanStruct rng $ \rng' ->
      withPrimVectorUnsafe ptext $ \ptext' ptextOff ptextLen -> do
        len <- pkEncryptLen enop ptextLen
        (a, _) <- allocPrimVectorUnsafe len $ \out -> do
          (a', _) <- allocPrimUnsafe @Int $ \outLen ->
            throwBotanIfMinus_ (hs_botan_pk_op_encrypt op' rng' out outLen ptext' ptextOff ptextLen)
          pure a'
        return a

newtype PKDecryption = PKDecryption BotanStruct

newPKDecryption :: PrivKey -> CBytes -> IO PKDecryption
newPKDecryption (PrivKey privKey) padding = do
  withCBytesUnsafe padding $ \padding' ->
    withBotanStruct privKey $ \privKey' ->
      PKDecryption <$> newBotanStruct (\op -> botan_pk_op_decrypt_create op privKey' padding' 0) botan_pk_op_decrypt_destroy

pkDecryptLen :: PKDecryption -> Int -> IO Int
pkDecryptLen (PKDecryption op) len = do
  withBotanStruct op $ \op' -> do
    (a, _) <- allocPrimUnsafe $ \ret -> throwBotanIfMinus_ (botan_pk_op_decrypt_output_length op' len ret)
    return a

pkDecrypt :: PKDecryption -> V.Bytes -> IO V.Bytes
pkDecrypt enop@(PKDecryption op) ciphertext = do
  withBotanStruct op $ \op' ->
    withPrimVectorUnsafe ciphertext $ \ciphertext' ciphertextOff ciphertextLen -> do
      len <- pkDecryptLen enop ciphertextLen
      (a, _) <- allocPrimVectorUnsafe len $ \out -> do
        (a', _) <- allocPrimUnsafe @Int $ \outLen ->
          throwBotanIfMinus_ (hs_botan_pk_op_decrypt op' out outLen ciphertext' ciphertextOff ciphertextLen)
        pure a'
      return a
