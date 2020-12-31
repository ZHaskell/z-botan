

data MACType (kmin :: Nat) (kmax :: Nat) (kmod :: Nat) where
    CBC_MAC  :: BlockCipherType
    CMAC     :: BlockCipherType
    GMAC     :: BlockCipherType
    HMAC     :: MACType 0 4096
    Poly1305 ::
    SipHash  ::
    X9'19_MAC ::
