{-|
Module      : Z.Crypto.FPE
Description : Format Preserving Encryption
Copyright   : Anjie, Dong Han, 2021
License     : BSD
Maintainer  : winterland1989@gmail.com
Stability   : experimental
Portability : non-portable

Format preserving encryption (FPE) refers to a set of techniques for encrypting data such that the ciphertext has the same format as the plaintext. For instance, you can use FPE to encrypt credit card numbers with valid checksums such that the ciphertext is also an credit card number with a valid checksum, or similarly for bank account numbers, US Social Security numbers, or even more general mappings like English words onto other English words.

The scheme currently implemented in botan is called FE1, and described in the paper Format Preserving Encryption by Mihir Bellare, Thomas Ristenpart, Phillip Rogaway, and Till Stegers. FPE is an area of ongoing standardization and it is likely that other schemes will be included in the future.

To encrypt an arbitrary value using FE1, you need to use a ranking method. Basically, the idea is to assign an integer to every value you might encrypt. For instance, a 16 digit credit card number consists of a 15 digit code plus a 1 digit checksum. So to encrypt a credit card number, you first remove the checksum, encrypt the 15 digit value modulo 1015, and then calculate what the checksum is for the new (ciphertext) number. Or, if you were encrypting words in a dictionary, you could rank the words by their lexicographical order, and choose the modulus to be the number of words in the dictionary.

-}
module Z.Crypto.FPE ( FPE, newFPE, encryptFPE, decryptFPE ) where

import           GHC.Generics
import           Z.Botan.FFI
import           Z.Botan.Exception
import           Z.Crypto.MPI
import qualified Z.Data.Vector as V
import qualified Z.Data.Text   as T
import           Z.Foreign

newtype FPE = FPE BotanStruct
    deriving (Show, Generic)
    deriving anyclass T.Print

-- | Initialize an FPE operation to encrypt/decrypt integers less than n. It is
--   expected that n is trivially factorable into small integers. Common usage
--   would be n to be a power of 10.
newFPE :: MPI     -- ^ mod (n)
       -> V.Bytes -- ^ key
       -> IO FPE
newFPE mpi key =
    withMPI mpi $ \ mpi' ->
    withPrimVectorUnsafe key $ \ key' keyOff keyLen ->
        FPE <$> newBotanStruct (\ fpe ->
            hs_botan_fpe_fe1_init fpe mpi' key' keyOff keyLen 3 1)
            botan_fpe_destroy

-- | Encrypts the value x modulo the value n using the key and tweak specified. Returns an integer less than n. The tweak is a value that does not need to be secret that parameterizes the encryption function. For instance, if you were encrypting a database column with a single key, you could use a per-row-unique integer index value as the tweak. The same tweak value must be used during decryption.
encryptFPE :: FPE
           -> MPI
           -> V.Bytes   -- ^ tweak
           -> IO MPI
encryptFPE (FPE fpe) mpi tweak = do
    mpi' <- copyMPI mpi
    withBotanStruct fpe $ \ fpe' ->
        withMPI mpi' $ \ mpi'' ->
        withPrimVectorUnsafe tweak $ \ t toff tlen ->
            throwBotanIfMinus_ (hs_botan_fpe_encrypt fpe' mpi'' t toff tlen)
    return mpi'


-- | Decrypts an FE1 ciphertext. The tweak must be the same as that provided to the encryption function. Returns the plaintext integer.
-- Note that there is not any implicit authentication or checking of data in FE1, so if you provide an incorrect key or tweak the result is simply a random integer.
decryptFPE :: FPE
           -> MPI
           -> V.Bytes   -- ^ tweak
           -> IO MPI
decryptFPE (FPE fpe) mpi tweak = do
    mpi' <- copyMPI mpi
    withBotanStruct fpe $ \ fpe' ->
        withMPI mpi' $ \ mpi'' ->
        withPrimVectorUnsafe tweak $ \ t toff tlen ->
            throwBotanIfMinus_ (hs_botan_fpe_decrypt fpe' mpi'' t toff tlen)
    return mpi'
