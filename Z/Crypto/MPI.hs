module Z.Crypto.MPI
  ( -- * RNG
    MPI, fromCInt, toWord32, byteSize, bitSize
    -- * Builder & Parser
  , toHex, toDecimal, fromHex, fromDecimal
    -- * Predicator
  , isNegative, isZero, isOdd, isEven
    -- * MPI specific
  , mulMod, powMod, modInverse
  ) where

import           Control.Monad
import           Data.Bits          hiding (bitSize)
import           Data.Word
import           GHC.Exts
import           GHC.Integer.GMP.Internals
import           GHC.Generics
import           GHC.Real
import           System.IO.Unsafe
import           Z.Data.ASCII
import           Z.Botan.FFI
import           Z.Botan.Exception
import           Z.Data.JSON         (JSON)
import qualified Z.Data.Array       as A
import qualified Z.Data.Builder     as B
import qualified Z.Data.Parser      as P
import qualified Z.Data.Vector      as V
import qualified Z.Data.Vector.Base as V
import qualified Z.Data.Text        as T
import qualified Z.Data.Text.Base   as T
import           Z.Crypto.RNG
import           Z.Foreign

-- | Opaque Botan Multiple Precision Integers.
newtype MPI = MPI BotanStruct

instance Eq MPI where
    {-# INLINE (==) #-}
    (MPI a) == (MPI b) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            withBotanStruct b $ \ btsb -> do
                r <- botan_mp_equal btsa btsb
                return $! r == 1

instance Ord MPI where
    {-# INLINE compare #-}
    (MPI a) `compare` (MPI b) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            withBotanStruct b $ \ btsb -> do
                (r, _) <- allocPrimUnsafe $ \ r -> botan_mp_cmp r btsa btsb
                return $! case (r :: CInt) of
                    1 -> GT
                    0 -> EQ
                    _ -> LT

instance Num MPI where
    {-# INLINE (+) #-}
    (MPI a) + (MPI b) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            withBotanStruct b $ \ btsb ->
                newMPI $ \ btsr -> botan_mp_add btsr btsa btsb
    {-# INLINE (-) #-}
    (MPI a) - (MPI b) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            withBotanStruct b $ \ btsb ->
                newMPI $ \ btsr -> botan_mp_sub btsr btsa btsb
    {-# INLINE (*) #-}
    (MPI a) * (MPI b) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            withBotanStruct b $ \ btsb ->
                newMPI $ \ btsr -> botan_mp_mul btsr btsa btsb

    {-# INLINE negate #-}
    negate (MPI a) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            newMPI (\ bts -> do
                botan_mp_set_from_mp bts btsa
                botan_mp_flip_sign bts)

    {-# INLINE abs #-}
    abs mp | isNegative mp = negate mp
           | otherwise = mp

    {-# INLINE signum #-}
    signum mp = case mp `compare` zero of
        LT -> -1
        EQ -> 0
        _  -> 1

    {-# INLINE fromInteger #-}
    fromInteger c
        | c == 0 = zero
        | otherwise = unsafeDupablePerformIO $ do
            mpa@(MutablePrimArray mba#)<- newPrimArray (I# (word2Int# siz#))
            void (exportIntegerToMutableByteArray c mba# 0## 1#)
            (PrimArray ba# :: PrimArray Word8) <- unsafeFreezePrimArray mpa
            r <- newMPI $ \ bts -> hs_botan_mp_from_bin bts ba# 0 (I# (word2Int# siz#))
            return $! if c < 0 then negate r else r
      where
        siz# = sizeInBaseInteger c 256#

instance Real MPI where
    {-# INLINE toRational #-}
    toRational mp = toInteger mp :% 1

instance Enum MPI where
    succ x               = x + 1
    pred x               = x - 1
    toEnum               = fromIntegral
    fromEnum             = fromIntegral
    {-# INLINE enumFrom #-}
    {-# INLINE enumFromThen #-}
    {-# INLINE enumFromTo #-}
    {-# INLINE enumFromThenTo #-}
    enumFrom x             = enumDeltaMPI   x 1
    enumFromThen x y       = enumDeltaMPI   x (y-x)
    enumFromTo x lim       = enumDeltaToMPI x 1     lim
    enumFromThenTo x y lim = enumDeltaToMPI x (y-x) lim

-- These RULES are copied from GHC.Enum
{-# RULES
"enumDeltaMPI"      [~1] forall x y.   enumDeltaMPI x y         = build (\c _ -> enumDeltaMPIFB c x y)
"efdtMPI"           [~1] forall x d l. enumDeltaToMPI x d l     = build (\c n -> enumDeltaToMPIFB  c n x d l)
"efdtMPI1"          [~1] forall x l.   enumDeltaToMPI x 1 l     = build (\c n -> enumDeltaToMPI1FB c n x l)

"enumDeltaToMPI1FB" [1] forall c n x.  enumDeltaToMPIFB c n x 1 = enumDeltaToMPI1FB c n x

"enumDeltaMPI"      [1] enumDeltaMPIFB    (:)     = enumDeltaMPI
"enumDeltaToMPI"    [1] enumDeltaToMPIFB  (:) []  = enumDeltaToMPI
"enumDeltaToMPI1"   [1] enumDeltaToMPI1FB (:) []  = enumDeltaToMPI1
 #-}

{-# INLINE [0] enumDeltaMPIFB #-}
-- See Note [Inline FB functions] in GHC.List
enumDeltaMPIFB :: (MPI -> b -> b) -> MPI -> MPI -> b
enumDeltaMPIFB c x0 d = go x0
  where go x = x `seq` (x `c` go (x+d))

{-# NOINLINE [1] enumDeltaMPI #-}
enumDeltaMPI :: MPI -> MPI -> [MPI]
enumDeltaMPI x d = x `seq` (x : enumDeltaMPI (x+d) d)
-- strict accumulator, so
--     head (drop 1000000 [1 .. ]
-- works

{-# INLINE [0] enumDeltaToMPIFB #-}
-- See Note [Inline FB functions] in GHC.List
-- Don't inline this until RULE "enumDeltaToMPI" has had a chance to fire
enumDeltaToMPIFB :: (MPI -> a -> a) -> a
                     -> MPI -> MPI -> MPI -> a
enumDeltaToMPIFB c n x delta lim
  | delta >= 0 = up_fb c n x delta lim
  | otherwise  = dn_fb c n x delta lim

{-# INLINE [0] enumDeltaToMPI1FB #-}
-- See Note [Inline FB functions] in GHC.List
-- Don't inline this until RULE "enumDeltaToMPI" has had a chance to fire
enumDeltaToMPI1FB :: (MPI -> a -> a) -> a
                      -> MPI -> MPI -> a
enumDeltaToMPI1FB c n x0 lim = go (x0 :: MPI)
                      where
                        go x | x > lim   = n
                             | otherwise = x `c` go (x+1)

{-# NOINLINE [1] enumDeltaToMPI #-}
enumDeltaToMPI :: MPI -> MPI -> MPI -> [MPI]
enumDeltaToMPI x delta lim
  | delta >= 0 = up_list x delta lim
  | otherwise  = dn_list x delta lim

{-# NOINLINE [1] enumDeltaToMPI1 #-}
enumDeltaToMPI1 :: MPI -> MPI -> [MPI]
-- Special case for Delta = 1
enumDeltaToMPI1 x0 lim = go (x0 :: MPI)
                      where
                        go x | x > lim   = []
                             | otherwise = x : go (x+1)

up_fb :: (MPI -> a -> a) -> a -> MPI -> MPI -> MPI -> a
up_fb c n x0 delta lim = go (x0 :: MPI)
                      where
                        go x | x > lim   = n
                             | otherwise = x `c` go (x+delta)
dn_fb :: (MPI -> a -> a) -> a -> MPI -> MPI -> MPI -> a
dn_fb c n x0 delta lim = go (x0 :: MPI)
                      where
                        go x | x < lim   = n
                             | otherwise = x `c` go (x+delta)

up_list :: MPI -> MPI -> MPI -> [MPI]
up_list x0 delta lim = go (x0 :: MPI)
                    where
                        go x | x > lim   = []
                             | otherwise = x : go (x+delta)
dn_list :: MPI -> MPI -> MPI -> [MPI]
dn_list x0 delta lim = go (x0 :: MPI)
                    where
                        go x | x < lim   = []
                             | otherwise = x : go (x+delta)

instance Integral MPI where
    {-# INLINE quotRem #-}
    (MPI a) `quotRem` (MPI b) = unsafeDupablePerformIO $ do
        withBotanStruct a $ \ btsa ->
            withBotanStruct b $ \ btsb ->
                newMPI' $ \ q ->
                    newMPI $ \ r ->
                        botan_mp_div q r btsa btsb

    {-# INLINE toInteger #-}
    toInteger mp@(MPI a)
        | isZero mp = 0
        | otherwise = unsafeWithMPI mp $ \ bts -> do
            mpa@(MutablePrimArray mba#) <- newPrimArray siz
            hs_botan_mp_to_bin bts mba# 0
            (PrimArray ba# :: PrimArray Word8) <- unsafeFreezePrimArray mpa
            let r = importIntegerFromByteArray ba# 0## (int2Word# siz#) 1#
            return $! if mp < 0 then negate r else r
      where
        siz@(I# siz#) = (byteSize mp)

instance Show MPI where
    show = T.toString

instance T.Print MPI where
    {-# INLINE toUTF8BuilderP #-}
    toUTF8BuilderP _  = toDecimal

zero :: MPI
zero = unsafeNewMPI (\ _ -> return ())

newMPI :: (BotanStructT -> IO a) -> IO MPI
newMPI f = do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    withBotanStruct mp f
    return (MPI mp)

newMPI' :: (BotanStructT -> IO a) -> IO (MPI, a)
newMPI' f = do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    r <- withBotanStruct mp f
    return (MPI mp, r)

copyMPI :: MPI -> IO MPI
copyMPI (MPI a) = do
    withBotanStruct a $ \ btsa -> do
        newMPI (\ bts -> botan_mp_set_from_mp bts btsa)

unsafeWithMPI :: MPI -> (BotanStructT -> IO a) -> a
unsafeWithMPI (MPI bts) f = unsafeDupablePerformIO (withBotanStruct bts f)

unsafeNewMPI :: (BotanStructT -> IO a) -> MPI
unsafeNewMPI f = unsafeDupablePerformIO $ do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    withBotanStruct mp f
    return (MPI mp)

unsafeNewMPI' :: (BotanStructT -> IO a) -> (MPI, a)
unsafeNewMPI' f = unsafeDupablePerformIO $ do
    mp <- newBotanStruct (\ bts -> botan_mp_init bts) botan_mp_destroy
    r <- withBotanStruct mp f
    return (MPI mp, r)

-- | Get 'MPI' 's byte size.
byteSize :: MPI -> Int
byteSize mp = fromIntegral @CSize . fst . unsafeWithMPI mp $ \ bts ->
    allocPrimUnsafe (botan_mp_num_bytes bts)

-- | Get 'MPI' 's bit size.
bitSize :: MPI -> Int
bitSize mp = fromIntegral @CSize . fst . unsafeWithMPI mp $ \ bts ->
    allocPrimUnsafe (botan_mp_num_bits bts)

-- | Set 'MPI' from an integer value.
fromCInt :: CInt -> MPI
fromCInt x = unsafeNewMPI $ \ bts ->
    botan_mp_set_from_int bts x

-- | Convert a MPI to 'Word32', the sign is ignored.
toWord32 :: HasCallStack => MPI -> Word32
toWord32 mp = fst . unsafeWithMPI mp $ \ bts ->
    allocPrimUnsafe (botan_mp_to_uint32 bts)

-- | Write a 'MPI' in decimal format, with negative sign if < 0.
toDecimal :: MPI -> B.Builder ()
toDecimal mp@(MPI bts) = do
    when (isNegative mp) (B.word8 MINUS)
    -- botan write \NUL terminator
    B.ensureN (byteSize mp * 3 + 1) $ \ (MutablePrimArray mba#) off ->
        withBotanStruct bts $ \ btst -> do
            hs_botan_mp_to_dec btst mba# off

-- | Parse a 'MPI' in decimal format, parse leading minus sign.
fromDecimal :: P.Parser MPI
fromDecimal = do
    sign <- P.peek
    let neg = sign == MINUS
    when neg P.skipWord8
    v@(V.PrimVector (A.PrimArray ba#) s l) <- P.takeWhile1 isDigit
    let (x, r) = unsafeNewMPI' $ \ bts -> do
            r' <- hs_botan_mp_set_from_dec bts ba# s l
            when (r' >= 0 && neg) (void $ botan_mp_flip_sign bts)
            return r'
    if (r < 0)
    then P.fail' $ "wrong decimal integer: " <> T.toText v
    else return x

-- | Write a 'MPI' in hexadecimal format(without '0x' prefix), the sign is ignored.
toHex :: MPI -> B.Builder ()
toHex mp@(MPI bts) =
    -- botan write \NUL terminator
    let !siz = byteSize mp `unsafeShiftL` 1
    in B.ensureN (siz + 1) $ \ (MutablePrimArray mba#) off ->
        withBotanStruct bts $ \ btst -> do
            _ <- hs_botan_mp_to_hex btst mba# off
            return (off+siz)

-- | Parse a 'MPI' in hexadecimal format(without '0x' prefix), no sign is allowed.
fromHex :: P.Parser MPI
fromHex = do
    v@(V.PrimVector (A.PrimArray ba#) s l) <- P.takeWhile1 isHexDigit
    let (x, r) = unsafeNewMPI' $ \ bts -> hs_botan_mp_set_from_hex bts ba# s l
    if (r < 0)
    then P.fail' $ "wrong hexadecimal integer: " <> T.toText v
    else return x

isNegative :: MPI -> Bool
isNegative mp = unsafeWithMPI mp $ \ bts -> do
    r <- botan_mp_is_negative bts
    return $! r == 1

isZero :: MPI -> Bool
isZero mp = unsafeWithMPI mp $ \ bts -> do
    r <- botan_mp_is_zero bts
    return $! r == 1

isOdd :: MPI -> Bool
isOdd mp = unsafeWithMPI mp $ \ bts -> do
    r <- botan_mp_is_odd bts
    return $! r == 1

isEven :: MPI -> Bool
isEven mp = unsafeWithMPI mp $ \ bts -> do
    r <- botan_mp_is_even bts
    return $! r == 1

--------------------------------------------------------------------------------

-- | mulMod x y mod = x times y modulo mod
mulMod :: MPI -> MPI -> MPI -> MPI
mulMod (MPI x) (MPI y) (MPI m) =
    unsafeNewMPI $ \ btsr ->
        withBotanStruct x $ \ btsx ->
            withBotanStruct y $ \ btsy ->
                withBotanStruct m $ \ btsm ->
                    botan_mp_mod_mul btsr btsx btsy btsm


-- | Modular exponentiation. powMod base exp mod = base power exp module mod
powMod :: MPI -> MPI -> MPI -> MPI
powMod (MPI x) (MPI y) (MPI m) =
    unsafeNewMPI $ \ btsr ->
        withBotanStruct x $ \ btsx ->
            withBotanStruct y $ \ btsy ->
                withBotanStruct m $ \ btsm ->
                    botan_mp_powmod btsr btsx btsy btsm

-- | Modular inverse, find an integer x so that @a⋅x ≡ 1  mod m@
--
-- If no modular inverse exists (for instance because in and modulus are not relatively prime), return 0.
modInverse :: MPI -> MPI -> MPI
modInverse (MPI x) (MPI y) =
    unsafeNewMPI $ \ btsr ->
        withBotanStruct x $ \ btsx ->
            withBotanStruct y $ \ btsy ->
                    botan_mp_mod_inverse btsr btsx btsy
