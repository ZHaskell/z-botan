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
import qualified Z.Data.Vector      as V
import           Prelude            hiding (lines)
-- import           Data.IORef

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
    -- some lines contains trailing spaces, e.g., tls_prf.vec
    V.dropWhileR isSpace <$> P.takeWhile (/= NEWLINE)

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

-- | Parse test data vectors of the form
--
--    -- @Salt == @
--    -- @Label == @
--    -- @Secret == @
--    -- @Output == @
--
-- and (unused) possible
--
--    -- @IKM == @
--    -- @XTS == @
--
-- See `./third_party/botan/src/tests/data/kdf/hkdf.vec`.
parseKDFTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseKDFTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_S
                       && w /= LETTER_L
                       && w /= LETTER_O
                       && w /= LETTER_I
                       && w /= LETTER_X
                       && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          _ -> do
              -- skip possible IKM and XTS
              ikm <- parseKeyValueLine "IKM" <|> pure mempty
              unless (V.null ikm)
                  P.skipWord8
              xts <- parseKeyValueLine "XTS" <|> pure mempty
              unless (V.null xts)
                  P.skipWord8
              salt <- parseKeyValueLine "Salt" <|> pure mempty
              -- and here the salt's value may be empty...: in the format: Salt = <\n>.
              P.peekMaybe >>= \case Just NEWLINE -> P.skipWord8
                                    _            -> return ()
              label <- parseKeyValueLine "Label" <|> pure mempty
              unless (V.null label)
                  P.skipWord8
              secret <- parseKeyValueLine "Secret"
              P.skipWord8
              -- in some test data files the "salt" is placed after "secret", e.g., "kdf1.vec"
              salt <- if V.null salt
                         then do salt <- parseKeyValueLine "Salt" <|> pure mempty
                                 -- and here the salt's value may be empty...: in the format: Salt = <\n>.
                                 P.peekMaybe >>= \case Just NEWLINE -> P.skipWord8
                                                       _            -> return ()
                                 return salt
                         else return salt
              -- in some test data files the "label" is placed after "secret", e.g., "sp800_56a.vec"
              label <- if V.null label
                         then do label <- parseKeyValueLine "Label" <|> pure mempty
                                 unless (V.null label)
                                     P.skipWord8
                                 return label
                         else return label
              o <- parseKeyValueLine "Output"
              go ((hexDecode' salt, hexDecode' label, hexDecode' secret, hexDecode' o):acc)

-- | Parse test data vectors of the form
--
--    -- @Salt == @
--    -- @Iterations == @
--    -- @Passphrase == @
--    -- @Output == @
--
-- See `./third_party/botan/src/tests/data/pbkdf/pbkdf1.vec`.
parsePBKDFTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(V.Bytes, Int, V.Bytes, V.Bytes)])]
parsePBKDFTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_S
                       && w /= LETTER_I
                       && w /= LETTER_P
                       && w /= LETTER_O
                       && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          _ -> do
              -- in some cases the "Salt" and "Iterations" is after "Passphrase"
              salt <- parseKeyValueLine "Salt" <|> pure mempty
              P.peekMaybe >>= \case Just NEWLINE -> P.skipWord8
                                    _            -> return ()
              iter <- parseKeyValueLine "Iterations" <|> pure mempty
              P.peekMaybe >>= \case Just NEWLINE -> P.skipWord8
                                    _            -> return ()
              passphrase <- parseKeyValueLine "Passphrase"
              P.skipWord8
              salt <- if V.null salt
                         then do salt <- parseKeyValueLine "Salt" <|> pure mempty
                                 P.peekMaybe >>= \case Just NEWLINE -> P.skipWord8
                                                       _            -> return ()
                                 return salt
                         else return salt
              iter <- if V.null iter
                         then do iter <- parseKeyValueLine "Iterations" <|> pure mempty
                                 P.peekMaybe >>= \case Just NEWLINE -> P.skipWord8
                                                       _            -> return ()
                                 return iter
                         else return iter
              o <- parseKeyValueLine "Output"
              go ((hexDecode' salt, (fromIntegral . decLoopIntegerFast) iter, passphrase, hexDecode' o):acc)


-- | Parse test data vectors of the form
--
--    -- @IV == @ (possible)
--    -- @Key == @
--    -- @In == @
--    -- @Out == @
--
-- See `./third_party/botan/src/tests/data/mac/cbcmac.vec`.
parseMACTestVector :: HasCallStack => CBytes -> IO [(V.Bytes, [(Maybe V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseMACTestVector = parseNamedTestVector (go [])
  where
    go acc = do
      P.skipWhile (\ w -> w /= LETTER_I
                       && w /= LETTER_K
                       && w /= LETTER_O
                       && w /= BRACKET_LEFT && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> do
              P.skipWhile (/= NEWLINE)
              P.skipWord8
              go acc
          Just BRACKET_LEFT -> return (acc, False)
          _ -> do
              -- in some cases the "Salt" and "Iterations" is after "Passphrase"
              iv <- optional $ parseKeyValueLine "IV"
              case iv of
                  Just iv' -> unless (V.null iv') P.skipWord8
                  Nothing  -> return ()
              key <- parseKeyValueLine "Key"
              P.skipWord8
              in_ <- parseKeyValueLine "In"
              P.skipWord8
              o <- parseKeyValueLine "Out"
              go ((fmap hexDecode' iv, hexDecode' key, hexDecode' in_, hexDecode' o):acc)

skipComment :: (t -> P.Parser b) -> t -> P.Parser b
{-# INLINE skipComment #-}
skipComment h acc = do
    P.skipWhile (/= NEWLINE)
    P.skipWord8
    h acc

-- | Parse test data vectors of the form:
--
--    -- @Key == @
--    -- @KEK == @
--    -- @Output == @
--
-- See `./third_party/botan/src/tests/data/keywrap/rfc3394.vec`.
parseKeyWrapVec :: HasCallStack => CBytes -> IO [(V.Bytes, V.Bytes, V.Bytes)]
parseKeyWrapVec = parseTestVector (h [])
  where
    h acc = do
      P.skipWhile (\ w -> w /= LETTER_K && w /= LETTER_O && w /= HASH)
      w <- P.peekMaybe
      case w of
          Nothing -> return (acc, True)
          Just HASH -> skipComment h acc
          _ -> do
            key <- parseKeyValueLine "Key"
            P.skipWord8
            kek <- parseKeyValueLine "KEK"
            P.skipWord8
            o <- parseKeyValueLine "Output"
            h ((hexDecode' key, hexDecode' kek, hexDecode' o) : acc)

-- | Parse test data vectors of the form:
--
--    -- [label]         -- [label]
--    -- @Key == @       -- @Key == @
--    -- @Input == @     -- @Output == @
--    -- @Output == @    -- @Input == @
--
-- See `./third_party/botan/src/tests/data/keywrap/`.
-- parseNistKeyWrapVec :: HasCallStack => CBytes -> IO [(V.Bytes ,[(V.Bytes, V.Bytes, V.Bytes)])]
-- parseNistKeyWrapVec = parseNamedTestVector (h [])
--     where
--       h acc = do
--         P.skipWhile $ \ w -> w /= LETTER_K
--                           && w /= LETTER_O
--                           && w /= BRACKET_LEFT && w /= HASH
--         w <- P.peekMaybe
--         case w of
--           Nothing -> return (acc, True)
--           Just HASH -> skipComment h acc
--           Just BRACE_LEFT -> return (acc, False)
--           _ -> do
--             key <- parseKeyValueLine "Key"
--             P.skipWord8
--             resTag <- liftIO $ newIORef False
--             res0 <- parseKeyValueLine "Input" <* (liftIO $ writeIORef resTag True) <|> parseKeyValueLine "Output"
--             P.skipWord8
--             res1 <- parseKeyValueLine "Input" <|> parseKeyValueLine "Output"
--             resTag' <- liftIO $ readIORef resTag
--             let (i, o) = if resTag' then (res0, res1) else (res1, res0)
--             h ((hexDecode' key, hexDecode' i, hexDecode' o) : acc)
