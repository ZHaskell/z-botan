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

parseHashTestVector :: CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes)])]
parseHashTestVector path = do
    withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \ f -> do
        bi <- newBufferedInput f
        let loopRead = do
                name <- readParser algoName bi
                (lines, eof) <- readParser (hashLines []) bi
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
    hashLines acc = do
        P.skipWhile (\ w -> w /= LETTER_I && w /= BRACKET_LEFT && w /= HASH)
        w <- P.peekMaybe
        case w of
            Nothing -> return (acc, True)
            Just HASH -> do
                P.skipWhile (/= NEWLINE)
                P.skipWord8
                hashLines acc
            Just BRACKET_LEFT -> return (acc, False)
            _ -> do
                i <- (P.bytes "In = " >> P.takeWhile (/= NEWLINE)) <|> (P.bytes "In =" >> return V.empty)
                P.skipWord8
                o <- P.bytes "Out = " >> P.takeWhile (/= NEWLINE) <|> (P.bytes "Out =" >> return V.empty)
                hashLines ((hexDecode' i, hexDecode' o):acc)
