#include <botan_all.h>
#include <HsFFI.h>

#ifndef HS_BOTAN
#define HS_BOTAN

class Callbacks : public Botan::TLS::Callbacks
{
    public:
        char* record_received_buffer;
        HsInt record_buffer_index;
        HsInt record_buffer_reading_index;
        char* emit_data_buffer;
        HsInt emit_buffer_index;

        Callbacks();
        void tls_emit_data(const uint8_t data[], size_t size) override;
        void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override;
        void tls_alert(Botan::TLS::Alert alert) override;
        bool tls_session_established(const Botan::TLS::Session& session) override;
        ~Callbacks();
};

/*
class Credentials : public Botan::Credentials_Manager {
    private:
        std::vector<Botan::Certificate_Store*> m_stores;
        std::unique_ptr<Botan::Private_Key*> m_key;
        std::vector<Botan::X509_Certificate> m_cert;
    public:
        Credentials( const char* ca_store
                   , const StgArrBytes** cert_chain_files
                   , const HsInt cert_chain_files_num
                   , const char* key_file) {
    }

    std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
        const std::string& type,
        const std::string& context) override
        {}

    std::vector<Botan::X509_Certificate> cert_chain(
        const std::vector<std::string>& cert_key_types,
        const std::string& type,
        const std::string& context) override
        { return m_cert; }

    Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
        const std::string& type,
        const std::string& context) override
        { }
};
*/

extern "C" {

////////////////////////////////////////////////////////////////////////////////
// FFI helper
// Codec

int hs_botan_hex_encode(const uint8_t *x, HsInt x_off, HsInt x_len, char *out);
int hs_botan_hex_encode_lower(const uint8_t *x, HsInt x_off, HsInt x_len, char *out);
HsInt hs_botan_hex_decode(const char* hex_str, HsInt in_off, HsInt in_len, uint8_t* out);

// RNG
int hs_botan_rng_add_entropy(botan_rng_t rng, const uint8_t *seed, HsInt off, HsInt len);

// Block Cipher
int hs_botan_block_cipher_set_key(botan_block_cipher_t bc, const uint8_t *key, HsInt key_off, HsInt key_len);
int hs_botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc
    , const uint8_t in[], HsInt off, uint8_t out[], HsInt blocks);
int hs_botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc
    , const uint8_t in[], HsInt off, uint8_t out[], HsInt blocks);

// Hash
int hs_botan_hash_update(botan_hash_t hash, const uint8_t *input, HsInt off, HsInt len);

// Cipher Mode
int hs_botan_cipher_set_key(botan_cipher_t cipher, const uint8_t* key, HsInt key_off, HsInt key_len);
int hs_botan_cipher_set_associated_data(botan_cipher_t cipher, const uint8_t* ad, HsInt ad_off, HsInt ad_len);
int hs_botan_cipher_start(botan_cipher_t cipher, const uint8_t* nonce, HsInt nonce_off, HsInt nonce_len);
// output buffer length should be at least equal to input length, 
// which must be larger than botan_cipher_get_update_granularity
// input_consumed == output_written
int hs_botan_cipher_update(botan_cipher_t cipher_obj,
                           uint8_t* output,
                           HsInt output_len,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len,
                           size_t* input_consumed);
// output buffer length should be at least equal to following call's result
// botan_cipher_output_length(cipher, input_length, &output_length)
// output_written may differ
int hs_botan_cipher_finish(botan_cipher_t cipher_obj,
                           uint8_t* output,
                           HsInt output_len,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len,
                           size_t* output_written);

////////////////////////////////////////////////////////////////////////////////
// TLS
#define HS_MAX_CIPHERTEXT_SIZE Botan::TLS::MAX_CIPHERTEXT_SIZE
#define HS_SESSION_ESTABLISHED -1
#define HS_FATAL_ALERT -2
#define HS_BOTAN_TLS_EXCEPTION -3

typedef Callbacks                   botan_callbacks_t;
/*
typedef struct {
    Botan::TLS::Client*             tls_client;
    Callbacks*                      callbacks;
    Credentials*                    client_credentials;
    Botan::RandomNumberGenerator*   rng;
    Botan::TLS::Session_Manager*    session_mgr;
    Botan::TLS::Policy*             policy;
} botan_tls_client_t;

typedef Credentials hs_credentials_t;

hs_credentials_t* new_credentials_t(
    const char* ca_store
#if __GLASGOW_HASKELL__ < 810
  , StgMutArrPtrs** cert_chain_files_arr
#else
  , StgArrBytes** cert_chain_files
#endif
  , const HsInt cert_chain_files_num
  , const char* key_file);

void* free_credentials_t(hs_credentials_t* cred);

botan_tls_client_t* new_tls_client();
void free_tls_client(botan_tls_client_t* client);
void hs_tls_received_data(botan_tls_client_t* client, const uint8_t buf[], size_t buf_size);
void hs_tls_send(botan_tls_client_t* client, const uint8_t buf[], size_t buf_size);
*/
    
}

#endif 
