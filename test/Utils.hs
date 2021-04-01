{-# LANGUAGE OverloadedStrings #-}


module Utils where

import           Control.Applicative
import           Z.IO
import qualified Z.IO.FileSystem    as FS
import           Z.Data.ASCII
import           Z.Data.Vector.Hex
import qualified Z.Data.Parser      as P
import           Z.Data.CBytes      (CBytes)
import qualified Z.Data.Vector      as V
import           Prelude            hiding (lines)

-- | Parse test data vector files.
-- See `./third_party/botan/src/tests/data/`.
parseNamedTestVector :: HasCallStack => P.Parser (x, Bool) -> CBytes -> IO [(V.Bytes, x)]
parseNamedTestVector p path  = do
    withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \ f -> do
        bi <- newBufferedInput f
        let loopRead = do
                name <- readParser algoName bi
                (lines, eof) <- readParser p bi
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

-- | Parse @key = value@ or @key  = value@ or @key =@ line
parseKeyValueLine :: V.Bytes -> P.Parser V.Bytes
parseKeyValueLine k1 = do
    P.bytes k1
    P.skipWhile (== SPACE)
    P.word8 EQUAL
    P.skipWhile (== SPACE)
    P.takeWhile (/= NEWLINE)

parseHashTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes)])]
parseHashTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_I && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          _ -> do
              i <- parseKeyValueLine "In"
              P.skipWord8
              o <- parseKeyValueLine "Out"
              go ((hexDecode' i, hexDecode' o):acc)

parseBlockCipherTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes)])]
parseBlockCipherTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_K && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          _ -> do
              key <- parseKeyValueLine "Key"
              P.skipWord8
              i <- parseKeyValueLine "In"
              P.skipWord8
              o <- parseKeyValueLine "Out"
              go ((hexDecode' key, hexDecode' i, hexDecode' o):acc)

parseCipherModeTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseCipherModeTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_K && w /= LETTER_N && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          Just w' -> do
              (key, nonce) <- if w' == LETTER_K
                  then do
                    key <- parseKeyValueLine "Key"
                    P.skipWord8
                    nonce <- parseKeyValueLine "Nonce"
                    P.skipWord8
                    return (key, nonce)
                  else do
                    nonce <- parseKeyValueLine "Nonce"
                    P.skipWord8
                    key <- parseKeyValueLine "Key"
                    P.skipWord8
                    return (key, nonce)
              i <- parseKeyValueLine "In"
              P.skipWord8
              o <- parseKeyValueLine "Out"
              go ((hexDecode' key, hexDecode' nonce, hexDecode' i, hexDecode' o):acc)

parseCipherAEADTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseCipherAEADTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_K && w /= LETTER_N && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          Just w' -> do
              (key, nonce) <- if w' == LETTER_K
                  then do
                    key <- parseKeyValueLine "Key"
                    P.skipWord8
                    nonce <- parseKeyValueLine "Nonce"
                    P.skipWord8
                    return (key, nonce)
                  else do
                    nonce <- parseKeyValueLine "Nonce"
                    P.skipWord8
                    key <- parseKeyValueLine "Key"
                    P.skipWord8
                    return (key, nonce)
              i <- parseKeyValueLine "In"
              P.skipWord8
              ad <- parseKeyValueLine "AD"
              P.skipWord8
              o <- parseKeyValueLine "Out"
              go ((hexDecode' key, hexDecode' nonce, hexDecode' i, hexDecode' ad, hexDecode' o):acc)


-- | Parse test data vector files.
-- See `./third_party/botan/src/tests/data/`.
parseTestVector ::
  HasCallStack =>
  -- | (txt, eof)
  P.Parser ([x], Bool) ->
  -- | path
  CBytes ->
  IO [x]
parseTestVector p path = do
  withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \f -> do
    bi <- newBufferedInput f
    let loopRead = do
          (txt, eof) <- readParser p bi
          if eof
            then return txt
            else do
              rest <- loopRead
              return $ txt ++ rest
    loopRead

-- | Parse test data vectors of the form:
--    -- @Password = @
--    -- @Passhash = @
-- See `./third_party/botan/src/tests/data/passhash/bcrypt.vec`.
parsePasswdHashTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, V.Bytes)]
parsePasswdHashTestVector = parseTestVector $ h []
  where
    h acc = do
      P.skipWhile $ \c ->
        c /= LETTER_P -- goto @Password = @ or @Passhash = @
          && c /= HASH -- deal with comment
      c <- P.peekMaybe
      case c of
        Nothing -> pure (acc, True) -- end of file
        Just HASH -> do
          P.skipWhile (/= NEWLINE) -- line comment
          P.skipWord8 -- skip @\n@
          h acc
        _ -> do
          passwd <- parseKeyValueLine "Password"
          P.skipWord8
          passhash <- parseKeyValueLine "Passhash"
          h $ (hexDecode' passwd, passhash) : acc
