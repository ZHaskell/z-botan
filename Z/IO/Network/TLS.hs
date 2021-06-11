

data CertStoreType
    = CertStoreFiles [CBytes]
    | MozillaCertStore
    | SystemCertStore

data Session = Session
    { sessionChannel :: BotanStruct
    , sessionUVStream :: UVStream
    , sessionCredMananger :: BotanStruct
    , sessionRNG :: BotanStruct
    }

closeSession :: Session -> IO ()
closeSession (Session ch uvm cred rng) = do
    close ch
    close uvm

data TLSServerConfig = TLSServerConfig
    { serverCertStore    :: Maybe CertStoreType
    , serverKeyCertPairs :: [(PrivKey, [Certs])]
    , serverSessionLimit :: (Int, Int)
    }


startTLSServer :: HasCallStack
               => TLSServerConfig
               -> (Session -> IO ())
               -> IO ()


data TLSServerConfig = TLSServerConfig
    { clientCertStore  :: CertStoreType
    , clientPrivateKey :: [(PrivKey, [Certs])]
    , clientSessionLimit :: (Int, Int)
    , clientServerInfo :: (T.Text, T.Text, Int)
    ,
    }
