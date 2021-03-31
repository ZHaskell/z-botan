{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Utils' where

import Z.Data.ASCII
  ( pattern BRACKET_LEFT,
    pattern BRACKET_RIGHT,
    pattern EQUAL,
    pattern HASH,
    pattern LETTER_P,
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
