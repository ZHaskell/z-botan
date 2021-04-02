{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Utils' where

import Z.Data.ASCII
  ( pattern BRACE_LEFT,
    pattern BRACKET_LEFT,
    pattern BRACKET_RIGHT,
    pattern EQUAL,
    pattern HASH,
    pattern LETTER_B,
    pattern LETTER_I,
    pattern LETTER_O,
    pattern LETTER_P,
    pattern LETTER_Q,
    pattern LETTER_S,
    pattern NEWLINE,
    pattern SPACE,
  )
import Z.Data.CBytes (CBytes, fromBytes)
import qualified Z.Data.Parser as P
import qualified Z.Data.Vector as V
import Z.IO
  ( HasCallStack,
    newBufferedInput,
    readParser,
    withResource,
  )
import qualified Z.IO.FileSystem as FS

-- | Parse test data vector files.
-- See `./third_party/botan/src/tests/data/`.
parseVec ::
  HasCallStack =>
  -- | (txt, eof)
  P.Parser ([x], Bool) ->
  -- | path
  CBytes ->
  IO [x]
parseVec p path = do
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

-- | Parse test data vector files.
-- Grp equipped with names.
-- See `./third_party/botan/src/tests/data/`.
parseVecNamed ::
  HasCallStack =>
  -- | (txt, eof)
  P.Parser ([x], Bool) ->
  -- | path
  CBytes ->
  IO [(V.Bytes, [x])]
parseVecNamed p path = do
  withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \f -> do
    bi <- newBufferedInput f
    let loopRead = do
          name <- readParser parseAlgoName bi
          (txt, eof) <- readParser p bi
          if eof
            then return [(name, txt)]
            else do
              rest <- loopRead
              return $ (name, txt) : rest
    loopRead

-- | Parse test data vectors of the form:
--    -- arg_0 = p_0
--    -- arg_n = p_n
--    -- [algoName]
--    -- ... ...
--    -- k_0 = v_0
--    -- k_n = v_0
--    -- ... ...
parseVecArgNamed ::
  HasCallStack =>
  -- | args parser
  P.Parser a ->
  -- | vectors parser
  P.Parser ([x], Bool) ->
  -- | path
  CBytes ->
  IO (a, [(V.Bytes, [x])])
parseVecArgNamed pa p path = do
  withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \f -> do
    bi <- newBufferedInput f
    args <- readParser pa bi
    let loopRead = do
          name <- readParser parseAlgoName bi
          (txt, eof) <- readParser p bi
          if eof
            then return [(name, txt)]
            else do
              rest <- loopRead
              return $ (name, txt) : rest
    ret <- loopRead
    return (args, ret)

-- | Parse test data vectors of the form:
--    -- [algoName]
--    -- arg_0 = p_0
--    -- arg_n = p_n
--    -- ... ...
--    -- k_0 = v_0
--    -- k_n = v_0
--    -- ... ...
parseVecNamedArg :: HasCallStack => P.Parser a -> P.Parser ([x], Bool) -> CBytes -> IO [(V.Bytes, a, [x])]
parseVecNamedArg pa p path = do
  withResource (FS.initFile path FS.O_RDONLY FS.DEFAULT_FILE_MODE) $ \f -> do
    bi <- newBufferedInput f
    let loopRead = do
          name <- readParser parseAlgoName bi
          args <- readParser pa bi
          (txt, eof) <- readParser p bi
          if eof
            then pure [(name, args, txt)]
            else do
              rest <- loopRead
              pure $ (name, args, txt) : rest
    loopRead

-- | Parse test data vectors of the form:
--    -- [algoName]
--    -- ... ...
--    -- k_0 = v_0
--    -- k_n = v_0
--    -- ... ...
parseAlgoName :: P.Parser V.Bytes
parseAlgoName = do
  P.skipWhile (/= BRACKET_LEFT) -- goto @[@
  P.skipWord8 -- skip @[@
  s <- P.takeWhile1 (/= BRACKET_RIGHT) -- get algoName
  P.skipWord8 -- skip @]@
  pure s

-- | Parse @key = value@ or @key  = value@ or @key =@ lines.
parseKeyValLn :: V.Bytes -> P.Parser V.Bytes
parseKeyValLn key = do
  P.bytes key -- goto @key =@
  P.skipWhile (== SPACE) -- skip @\ @ of any length
  P.word8 EQUAL -- skip @=@
  P.skipWhile (== SPACE) -- skip @\ @ of any length
  P.takeWhile (/= NEWLINE) -- get value

-- | Parse test data vectors of the form:
--    -- @Password = @
--    -- @Passhash = @
-- See `./third_party/botan/src/tests/data/passhash/bcrypt.vec`.
parsePasswdHashVec ::
  HasCallStack =>
  -- | path
  CBytes ->
  IO [(CBytes, V.Bytes)]
parsePasswdHashVec = parseVec $ h []
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
          passwd <- parseKeyValLn "Password"
          P.skipWord8
          passhash <- parseKeyValLn "Passhash"
          h $ (fromBytes passwd, passhash) : acc

-- | Parse test data vectors of the form:
--    -- @Secret = @
--    -- @Basepoint = @
--    -- @Out = @
-- See `./third_party/botan/src/tests/data/pubkey/c25519_scalar.vec`.
parsePubKeyScalar ::
  HasCallStack =>
  -- | path
  CBytes ->
  IO [(V.Bytes, V.Bytes, V.Bytes)]
parsePubKeyScalar = parseVec $ h []
  where
    h acc = do
      P.skipWhile $ \c ->
        c /= LETTER_S -- Secret
          && c /= LETTER_B -- Basepoint
          && c /= LETTER_O -- Out
      c <- P.peekMaybe
      case c of
        Nothing -> pure (acc, True)
        Just HASH -> do
          P.skipWhile (/= NEWLINE)
          P.skipWord8
          h acc
        _ -> do
          secret <- parseKeyValLn "Secret"
          P.skipWord8
          basepoint <- parseKeyValLn "Basepoint"
          P.skipWord8
          out <- parseKeyValLn "Out"
          h $ (secret, basepoint, out) : acc

skipComment :: (t -> P.Parser a) -> t -> P.Parser a
skipComment h acc = do
  P.skipWhile (/= NEWLINE)
  P.skipWord8
  h acc

parseDHInvalid ::
  HasCallStack =>
  CBytes ->
  IO
    ( ( V.Bytes, -- G
        V.Bytes, -- P
        V.Bytes -- Q
      ),
      [(V.Bytes, [V.Bytes])] -- algoName, [InvalidKey]
    )
parseDHInvalid = parseVecArgNamed (pa []) $ h []
  where
    pa acc = do
      P.skipWhile (`notElem` [LETTER_P, LETTER_P, LETTER_Q, HASH])
      c <- P.peek
      case c of
        HASH -> skipComment pa acc
        _ -> do
          g <- parseKeyValLn "G"
          P.skipWord8
          p <- parseKeyValLn "P"
          P.skipWord8
          q <- parseKeyValLn "Q"
          P.skipWord8
          return (g, p, q)
    h acc = do
      P.skipWhile $ \c -> c /= LETTER_I && c /= BRACKET_LEFT && c /= HASH
      c <- P.peekMaybe
      case c of
        Nothing -> pure (acc, True)
        Just HASH -> skipComment h acc
        Just BRACE_LEFT -> pure (acc, False)
        _ -> do
          invalidKey <- parseKeyValLn "InvalidKey"
          h (invalidKey : acc)

-- | See `./third_party/botan/src/tests/data/argon2.vec`.
parseArgon :: HasCallStack => CBytes -> IO [(V.Bytes, (V.Bytes, V.Bytes, V.Bytes), [(V.Bytes, V.Bytes, V.Bytes, V.Bytes, V.Bytes)])]
parseArgon = parseVecNamedArg (p []) (h [])
  where
    p acc = undefined
    h acc = undefined
