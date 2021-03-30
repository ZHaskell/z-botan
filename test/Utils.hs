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

parseTestVector :: HasCallStack => P.Parser (x, Bool) -> CBytes -> IO [(V.Bytes, x)]
parseTestVector p path  = do
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
parseKeyValueLine k1 =
    (do P.bytes k1
        P.skipWhile (== SPACE)
        P.word8 EQUAL
        P.skipWhile (== SPACE)
        P.takeWhile (/= NEWLINE))

parseHashTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes)])]
parseHashTestVector = parseTestVector (go [])
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
parseBlockCipherTestVector = parseTestVector (go [])
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
parseCipherModeTestVector = parseTestVector (go [])
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
parseCipherAEADTestVector = parseTestVector (go [])
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
