module Main (main) where

import Distribution.Pretty
import Distribution.Simple
import Distribution.Simple.Setup
import Distribution.Simple.LocalBuildInfo
import Distribution.Verbosity
import Distribution.Simple.Utils
import Distribution.Simple.Program
import Distribution.Simple.Program.Db
import Distribution.System
import Distribution.Utils.NubList
import Distribution.Types.Library
import Distribution.Types.BuildInfo
import Distribution.Types.LocalBuildInfo
import Distribution.Types.PackageDescription
import Data.Maybe
import Data.List
import System.Directory
import System.FilePath
import qualified System.Environment as System

main :: IO ()
main = do
    mainArgs <- System.getArgs
    if head mainArgs == "configure"
    then defaultMainWithHooksArgs simpleUserHooks {
            postConf = \ args flags pkg_descr lbi -> do
                let verbosity = fromFlag (configVerbosity flags)
                    baseDir lbi' = fromMaybe "" (takeDirectory <$> cabalFilePath lbi')
                    configFile = baseDir lbi </> "third_party" </> "botan" </> "configure.py"
                    configFolder = baseDir lbi </> "third_party" </> "botan"
                confExists <- doesFileExist configFile
                if confExists
                  then runConfigureScript configFolder configFile verbosity flags lbi
                  else die' verbosity "botan configure script not found."

                postConf simpleUserHooks args flags pkg_descr lbi
        ,   regHook = \ _ _ _ _ -> return ()
        } ("--with-gcc=c++":mainArgs)
    else defaultMain


runConfigureScript :: FilePath -> FilePath -> Verbosity -> ConfigFlags -> LocalBuildInfo -> IO ()
runConfigureScript configFolder configFile verbosity flags lbi = do
    env <- System.getEnvironment
    configureFile <- makeAbsolute configFile

    let extraPath = fromNubList $ configProgramPathExtra flags
        spSep = [searchPathSeparator]
        pathEnv = maybe (intercalate spSep extraPath)
                ((intercalate spSep extraPath ++ spSep)++) $ lookup "PATH" env
        pyProg = simpleProgram "python3"
        progDb = modifyProgramSearchPath
            (\p -> map ProgramSearchPathDir extraPath ++ p) emptyProgramDb
        overEnv = [("PATH", Just pathEnv) | not (null extraPath)]
        hp@(Platform  arch os) = hostPlatform lbi
        maybeHostFlag =
            if hp == buildPlatform
            then []
            else ["--cpu=" ++ show (pretty arch), "--os=" ++ show (pretty os)]

        -- pass amalgamation to produce botan_all.cpp
        args = configureFile:"--amalgamation":maybeHostFlag

    pyConfiguredProg <- lookupProgram pyProg
                      `fmap` configureProgram  verbosity pyProg progDb
    case pyConfiguredProg of
      Just py -> runProgramInvocation verbosity $
                 (programInvocation (py {programOverrideEnv = overEnv}) args)
                 { progInvokeCwd = Just configFolder }
      Nothing -> die' verbosity notFoundMsg
  where
      notFoundMsg = "The package's dep(botan) has a 'configure.py' script. "
               ++ "This requires python is discoverable in your path."



