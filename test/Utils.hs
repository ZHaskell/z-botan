{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Utils where

import           Control.Applicative
import           Control.Monad
import           Z.IO
import qualified Z.IO.FileSystem    as FS
import           Z.Data.ASCII
import           Z.Data.Vector.Hex
import qualified Z.Data.Parser      as P
import           Z.Data.Parser.Numeric (decLoopIntegerFast)
import           Z.Data.CBytes      (CBytes)
import qualified Z.Data.CBytes      as CB
import qualified Z.Data.Vector      as V
import qualified Z.Data.Text        as T
import           Prelude            hiding (lines, mod)
-- import           Data.IORef

-- | Parse test data vector files.
-- See `./third_party/botan/src/tests/data/`.
parseNamedTestVector :: HasCallStack => P.Parser x -> CBytes -> IO [(V.Bytes, [x])]
parseNamedTestVector p path  = do
    withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \ f -> do
        bi <- newBufferedInput f
        let loopRead = do
                name <- readParser algoName bi
                (lines, eof) <- readParser (go []) bi
                if eof
                then return [(name, lines)]
                else do
                    rest <- loopRead
                    return ((name, lines):rest)
        loopRead
  where
    algoName = do
        P.skipWhile (/= BRACKET_LEFT)
        P.skipWord8
        n <- P.takeWhile1 (/= BRACKET_RIGHT)
        P.skipWord8
        return n

    go acc = do
        P.skipWhile (== NEWLINE)
        w <- P.peekMaybe
        case w of
            Nothing -> return (acc, True)
            Just HASH -> skipComment >> go acc
            Just BRACKET_LEFT -> return (acc, False)
            _ -> do
                x <- p
                go (x:acc)

-- | Parse test data vector files.
-- See `./third_party/botan/src/tests/data/`.
parseTestVector :: HasCallStack => P.Parser x -> CBytes -> IO [x]
parseTestVector p path = do
  withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \f -> do
    bi <- newBufferedInput f
    readParser (h []) bi
  where
    h acc = do
        P.skipWhile (== NEWLINE)
        c <- P.peekMaybe
        case c of
            Nothing -> pure acc
            Just HASH -> skipComment >> h acc
            _ -> do
                x <- p
                h (x:acc)


-- | Parse @key = value@ or @key  = value@ or @key =@ line
parseKeyValueLines :: P.Parser [(V.Bytes, V.Bytes)]
parseKeyValueLines = go []
  where
    go acc = do
        mw <- P.peekMaybe
        case mw of
            Just w ->
                if w == NEWLINE
                then return acc
                else do
                    k <- P.takeWhile (/= SPACE)
                    P.skipWhile (== SPACE)
                    P.word8 EQUAL
                    P.skipWhile (== SPACE)
                    -- some lines contains trailing spaces, e.g., tls_prf.vec
                    v <- V.dropWhileR isSpace <$> P.takeWhile (/= NEWLINE)
                    P.skipWord8 <|> return ()
                    go ((k, v):acc)
            _ -> return acc

skipComment :: P.Parser ()
{-# INLINE skipComment #-}
skipComment = do
    P.skipWhile (/= NEWLINE)
    P.skipWhile (== NEWLINE)

lookupOrEmpty :: [(V.Bytes, V.Bytes)] -> V.Bytes -> V.Bytes
lookupOrEmpty m k = maybe V.empty id (lookup k m)

parseHashTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes)])]
parseHashTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let i = lookupOrEmpty m "In"
    let o = lookupOrEmpty m "Out"
    return (hexDecode' i, hexDecode' o)

parseBlockCipherTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes)])]
parseBlockCipherTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let key = lookupOrEmpty m "Key"
    let i = lookupOrEmpty m "In"
    let o = lookupOrEmpty m "Out"
    return (hexDecode' key, hexDecode' i, hexDecode' o)

parseCipherModeTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseCipherModeTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let key = lookupOrEmpty m "Key"
    let nonce = lookupOrEmpty m "Nonce"
    let i = lookupOrEmpty m "In"
    let o = lookupOrEmpty m "Out"
    return (hexDecode' key, hexDecode' nonce, hexDecode' i, hexDecode' o)

parseCipherAEADTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseCipherAEADTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let key = lookupOrEmpty m "Key"
    let nonce = lookupOrEmpty m "Nonce"
    let i = lookupOrEmpty m "In"
    let o = lookupOrEmpty m "Out"
    let ad = lookupOrEmpty m "AD"
    return (hexDecode' key, hexDecode' nonce, hexDecode' i, hexDecode' ad, hexDecode' o)


parsePasswdHashTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, V.Bytes)]
parsePasswdHashTestVector = parseTestVector $ do
    m <- parseKeyValueLines
    let passwd = lookupOrEmpty m "Password"
    let passhash = lookupOrEmpty m "Passhash"
    return (hexDecode' passwd, passhash)

parseKDFTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseKDFTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let ikm = lookupOrEmpty m "IKM"
    let xts = lookupOrEmpty m "XTS"
    let salt = lookupOrEmpty m "Salt"
    let label = lookupOrEmpty m "Label"
    let secret = lookupOrEmpty m "Secret"
    let o = lookupOrEmpty m "Output"
    return (hexDecode' salt, hexDecode' label, hexDecode' secret, hexDecode' o)

parsePBKDFTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, Int, T.Text, V.Bytes)])]
parsePBKDFTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let salt = lookupOrEmpty m "Salt"
    let iter = lookupOrEmpty m "Iterations"
    let passphrase = lookupOrEmpty m "Passphrase"
    let o = lookupOrEmpty m "Output"
    return (hexDecode' salt , (fromIntegral . decLoopIntegerFast) iter , T.validate passphrase , hexDecode' o)

parseMACTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(Maybe V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseMACTestVector = parseNamedTestVector $ do
    m <- parseKeyValueLines
    let iv = lookup "IV" m
    let key = lookupOrEmpty m "Key"
    let in_ = lookupOrEmpty m "In"
    let out = lookupOrEmpty m "Out"
    return (fmap hexDecode' iv, hexDecode' key, hexDecode' in_, hexDecode' out)

parseKeyWrapVec :: HasCallStack => CBytes -> IO [(V.Bytes, V.Bytes, V.Bytes)]
parseKeyWrapVec = parseTestVector $ do
    m <- parseKeyValueLines
    let key = lookupOrEmpty m "Key"
    let kek = lookupOrEmpty m "KEK"
    let o = lookupOrEmpty m "Output"
    return (hexDecode' key, hexDecode' kek, hexDecode' o)

parseFPEVec :: HasCallStack => CBytes -> IO [(V.Bytes, V.Bytes, V.Bytes, V.Bytes, V.Bytes)]
parseFPEVec = parseTestVector $ do
    m <- parseKeyValueLines
    let mod = lookupOrEmpty m "Mod"
    let i = lookupOrEmpty m "In"
    let o = lookupOrEmpty m "Out"
    let key = lookupOrEmpty m "Key"
    let tweak = lookupOrEmpty m "Tweak"
    return (mod, i, o, hexDecode' key, hexDecode' tweak)
