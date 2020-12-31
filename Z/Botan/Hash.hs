module Z.Botan.Hash where

import           Control.Concurrent.STM
import           Data.Word
import           Data.Function
import           Data.Proxy
import           Foreign.ForeignPtr
import           Foreign.Ptr
import           GHC.Generics
import           GHC.TypeNats
import           Z.Botan.Exception
import           Z.Botan.FFI
import           Z.Data.CBytes      as CB
import           Z.Data.JSON         (EncodeJSON, ToValue, FromValue)
import qualified Z.Data.Vector      as V
import qualified Z.Data.Text        as T
import           Z.Foreign
import           Z.IO.BIO
import           System.IO.Unsafe

{- | Available Hashs

Hash functions are one-way functions, which map data of arbitrary size to a fixed output length @a@. Most of the hash functions in Botan are designed to be cryptographically secure, which means that it is computationally infeasible to create a collision (finding two inputs with the same hash) or preimages (given a hash output, generating an arbitrary input with the same hash). But note that not all such hash functions meet their goals, in particular MD4 and MD5 are trivially broken. However they are still included due to their wide adoption in various protocols.

-}
data HashType
      -- | A recently designed hash function. Very fast on 64-bit processors.
      -- Can output a hash of any length between 1 and 64 bytes,
      -- this is specified by passing desired byte length.
    = BLAKE2b Int
      -- | Alias for @Blake2b 32@
    | BLAKE2b256
      -- | Alias for @Blake2b 64@
    | BLAKE2b512
      -- | An older (and incompatible) variant of SHA-3, but sometimes used. Prefer SHA-3 in new code.
    | Keccak1600
      -- | An old hash function that is now known to be trivially breakable.
      -- It is very fast, and may still be suitable as a (non-cryptographic) checksum.
    | MD4
      -- | Widely used, now known to be broken.
    | MD5
      -- | A 160 bit hash function, quite old but still thought to be secure
      -- (up to the limit of 2**80 computation required for a collision which is possible
      -- with any 160 bit hash function). Somewhat deprecated these days.
    | RIPEMD160
      -- | Widely adopted NSA designed hash function.
      -- Starting to show significant signs of weakness, and collisions can now be generated. Avoid in new designs.
    | SHA160
      -- | Relatively fast 256 bit hash function, thought to be secure.
      -- Also includes the variant SHA-224. There is no real reason to use SHA-224.
    | SHA256
    | SHA224
      -- | SHA-512 is faster than SHA-256 on 64-bit processors.
      -- Also includes the truncated variants SHA-384 and SHA-512/256,
      -- which have the advantage of avoiding message extension attacks.
    | SHA512
    | SHA384
    | SHA512_256
      -- | The new NIST standard hash. Fairly slow.
      -- Supports 224, 256, 384 or 512 bit outputs.
      -- SHA-3 is faster with smaller outputs. Use as “SHA3_256” or “SHA3_512”.
      -- Plain “SHA-3” selects default 512 bit output.
    | SHA3_224
    | SHA3_256
    | SHA3_384
    | SHA3_512
      -- | These are actually XOFs (extensible output functions) based on SHA-3,
      -- which can output a value of any byte length. For example “SHAKE128 @128”
      -- will produce 1024 bits of output.
    | SHAKE128 Int
    | SHAKE256 Int
      -- | Chinese national hash function, 256 bit output. Widely used in industry there.
      -- Fast and seemingly secure, but no reason to prefer it over SHA-2 or SHA-3 unless required.
    | SM3
      -- | A contender for the NIST SHA-3 competition. Very fast on 64-bit systems. Can output a hash of any length between 1 and 64 bytes. It also accepts an optional “personalization string” which can create variants of the hash. This is useful for domain separation.
    | Skein512 Int CBytes
      -- | Newly designed Russian national hash function.
      -- Due to use of input-dependent table lookups, it is vulnerable to side channels.
      -- There is no reason to use it unless compatibility is needed.
      -- Warning: The Streebog Sbox has recently been revealed to have a hidden structure
      -- which interacts with its linear layer in a way which may provide a backdoor when used in certain ways.
      -- Avoid Streebog if at all possible.
    | Streebog256
    | Streebog512
      -- | A 512-bit hash function standardized by ISO and NESSIE.
      -- Relatively slow, and due to the table based implementation it is potentially vulnerable
      -- to cache based side channels.
    | Whirlpool
      -- | Parallel simply concatenates multiple hash functions.
      --   For example “Parallel SHA256 SHA512 outputs a 256+512 bit hash created by hashing the input
      --   with both SHA256 and SHA512 and concatenating the outputs.
    | Parallel HashType HashType
      -- | Checksums, not suitable for cryptographic use, but can be used for error checking purposes.
    | Adler32
    | CRC24
    | CRC32
  deriving (Show, Read, Eq, Ord, Generic)
  deriving anyclass (T.Print, EncodeJSON, ToValue, FromValue)

hashTypeToCBytes :: HashType -> CBytes
hashTypeToCBytes h = case h of
    BLAKE2b siz  -> CB.concat [ "Blake2b(" , sizeCBytes siz, ")"]
    BLAKE2b256   -> "Blake2b(256)"
    BLAKE2b512   -> "Blake2b(512)"
    Keccak1600   -> "Keccak1600"
    MD4          -> "MD4"
    MD5          -> "MD5"
    RIPEMD160    -> "RIPEMD-160"
    SHA160       -> "SHA-160"
    SHA224       -> "SHA-224"
    SHA256       -> "SHA-256"
    SHA512       -> "SHA-512"
    SHA384       -> "SHA-384"
    SHA512_256   -> "SHA-512-256"
    SHA3_224     -> "SHA-3(224)"
    SHA3_256     -> "SHA-3(256)"
    SHA3_384     -> "SHA-3(384)"
    SHA3_512     -> "SHA-3(512)"
    SHAKE128 siz -> CB.concat [ "SHAKE-128(" , sizeCBytes siz , ")"]
    SHAKE256 siz -> CB.concat [ "SHAKE-256(" , sizeCBytes siz , ")"]
    SM3          -> "SM3"
    Skein512 siz b -> CB.concat [ "Skein-512(" , sizeCBytes siz, "," , b , ")"]
    Streebog256  -> "Streebog-256"
    Streebog512  -> "Streebog-512"
    Whirlpool    -> "Whirlpool"
    Parallel h1 h2 -> CB.concat [ "Parallel("
                              , hashTypeToCBytes h1
                              , ","
                              , hashTypeToCBytes h2
                              , ")"]
    Adler32      -> "Adler32"
    CRC24        -> "CRC24"
    CRC32        -> "CRC32"
  where
    sizeCBytes = CB.fromText . T.toText

-- | A Botan Hash Object.
data Hash = Hash
    { getHashStruct :: BotanStruct
    , getHashName :: CBytes
    , getHashSize :: Int
    }
    deriving (Show, Eq, Ord, Generic)
    deriving anyclass T.Print

newHash :: HasCallStack => HashType -> IO Hash
newHash typ = do
    let name = hashTypeToCBytes typ
    bs <- newBotanStruct
        (\ bts -> withCBytesUnsafe name $ \ pt ->
            (botan_hash_init bts pt 0))
        botan_hash_destroy
    (osiz, _) <- withBotanStruct bs $ \ pbs ->
        allocPrimUnsafe $ \ pl ->
            botan_hash_output_length pbs pl
    return (Hash bs name osiz)

-- | Copies the state of the hash object to a new hash object.
copyHash :: HasCallStack => Hash -> IO Hash
copyHash (Hash bts0 name siz) = do
    s <- newBotanStruct
        (\ bts -> withCBytesUnsafe name $ \ pt ->
            withBotanStruct bts0 $ \ pbts0 ->
            (botan_hash_copy_state bts pbts0))
        botan_hash_destroy
    return (Hash s name siz)

-- | Reset the state of this object back to clean, as if no input has been supplied.
clearHash :: HasCallStack => Hash -> IO ()
clearHash (Hash bts _ _) =
    throwBotanIfMinus_ (withBotanStruct bts botan_hash_clear)

-- | Feed a chunk of input into a hash object.
updateHash :: Hash -> V.Bytes -> IO ()
updateHash (Hash bts _ _) bs =
    withBotanStruct bts $ \ pbts ->
        withPrimVectorUnsafe bs $ \ pbs off len ->
            throwBotanIfMinus_ (hs_botan_hash_update pbts pbs off len)

-- | Compute hash value.
finalHash :: HasCallStack => Hash -> IO V.Bytes
{-# INLINABLE finalHash #-}
finalHash (Hash bts _ siz) =
    withBotanStruct bts $ \ pbts -> do
        (bs, r) <- allocPrimVectorUnsafe siz $ \ pout ->
            botan_hash_final pbts pout
        throwBotanIfMinus_ (return r)
        return bs

{-| Trun 'Hash' to a 'V.Bytes' sink, update 'Hash' by write bytes to the sink.

@
import Z.Data.CBytes
import Z.Data.Vector.Hex
import Z.Botan.Hash
import Z.IO

-- | Calculate SHA256 and MD5 checksum for a file in one streaming pass.
sha256AndMd5File :: CBytes -> IO (HexBytes, HexBytes)
sha256AndMd5File f =
    withResource (sourceFromFile f) $ \ src -> do
        md5 <- newHash MD5
        sha256 <- newHash SHA256
        runBIO $ src >|> (joinSink (sinkToHash md5) (sinkToHash sha256))
        h1 <- finalHash md5
        h2 <- finalHash sha256
        return (HexBytes h1, HexBytes h2)
@
-}
sinkToHash :: Hash -> Sink V.Bytes
{-# INLINABLE sinkToHash #-}
sinkToHash h = BIO push_ pull_
  where
    push_ x = updateHash h x >> return Nothing
    pull_ = return Nothing

-- | Directly compute a message's hash.
hash :: HasCallStack => HashType -> V.Bytes -> V.Bytes
{-# INLINABLE hash #-}
hash ht inp = unsafePerformIO $ do
    h <- newHash ht
    updateHash h inp
    finalHash h

-- | Directly compute a chunked message's hash.
hashChunks:: HasCallStack => HashType -> [V.Bytes] -> V.Bytes
{-# INLINABLE hashChunks #-}
hashChunks ht inp = unsafePerformIO $ do
    h <- newHash ht
    mapM_ (updateHash h) inp
    finalHash h
