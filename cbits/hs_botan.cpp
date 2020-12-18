#include <hs_botan.h>
#include <iostream>


////////////////////////////////////////////////////////////////////////////////
// FFI Helper
// Codec

int hs_botan_hex_encode(const uint8_t *x, HsInt x_off, HsInt x_len, char *out){
    return botan_hex_encode(x+x_off, x_len, out, 0);
}
int hs_botan_hex_encode_lower(const uint8_t *x, HsInt x_off, HsInt x_len, char *out){
    return botan_hex_encode(x+x_off, x_len, out, BOTAN_FFI_HEX_LOWER_CASE);
}
HsInt hs_botan_hex_decode(const char* hex_str, HsInt in_off, HsInt in_len, uint8_t* out){
    size_t* out_size;
    int r = botan_hex_decode(hex_str+in_off, in_len, out, out_size);
    if (r < 0) return (HsInt)r;
    return (HsInt)out_size;
}

// RNG

int hs_botan_rng_add_entropy(botan_rng_t rng, const uint8_t *seed, HsInt off, HsInt len){
    return botan_rng_add_entropy(rng, seed+off, len);
}

// Block cipher
int hs_botan_block_cipher_set_key(botan_block_cipher_t bc, const uint8_t *key, HsInt key_off, HsInt key_len){
    return botan_block_cipher_set_key(bc, key+key_off, key_len);
}
int hs_botan_block_cipher_encrypt_blocks(botan_block_cipher_t bc
    , const uint8_t in[], HsInt off, uint8_t out[], HsInt blocks){
    return botan_block_cipher_encrypt_blocks(bc, in+off, out, blocks);
}
int hs_botan_block_cipher_decrypt_blocks(botan_block_cipher_t bc
    , const uint8_t in[], HsInt off, uint8_t out[], HsInt blocks){
    return botan_block_cipher_decrypt_blocks(bc, in+off, out, blocks);
}

// Hash
int hs_botan_hash_update(botan_hash_t hash, const uint8_t *input, HsInt off, HsInt len){
    return botan_hash_update(hash, input+off, len);
}

// Cipher Mode
int hs_botan_cipher_set_associated_data(botan_cipher_t cipher, const uint8_t* ad, HsInt ad_off, HsInt ad_len){
    return botan_cipher_set_associated_data(cipher, ad+ad_off, ad_len);
}

int hs_botan_cipher_set_key(botan_cipher_t cipher, const uint8_t* key, HsInt key_off, HsInt key_len){
    return botan_cipher_set_key(cipher, key+key_off, key_len);
}

int hs_botan_cipher_start(botan_cipher_t cipher, const uint8_t* nonce, HsInt nonce_off, HsInt nonce_len){
    return botan_cipher_start(cipher, nonce+nonce_off, nonce_len);
}

int hs_botan_cipher_update(botan_cipher_t cipher,
                           uint8_t* output,
                           HsInt output_len,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len,
                           size_t* input_consumed){
    // we dont care, because it equals to input_consumed
    size_t output_written;
    return botan_cipher_update(cipher, 0, output, output_len
        , &output_written, input+input_off, input_len, input_consumed);
}
int hs_botan_cipher_finish(botan_cipher_t cipher,
                           uint8_t* output,
                           HsInt output_len,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len,
                           size_t* output_written){
    // we dont care, because it's the last call
    size_t input_consumed;
    return botan_cipher_update(cipher, BOTAN_CIPHER_UPDATE_FLAG_FINAL, output, output_len
        , output_written, input+input_off, input_len, &input_consumed);
}
/*
////////////////////////////////////////////////////////////////////////////////

Callbacks::Callbacks(){
    // hold data to be read to Haskell side
    record_received_buffer = (char*)malloc(Botan::TLS::MAX_CIPHERTEXT_SIZE);
    // record_received_buffer's size
    record_buffer_index = 0;
    // record_received_buffer's size
    record_buffer_reading_index = 0;
    // hold data to be send via tcp, also used as err message buffer
    emit_data_buffer = (char*)malloc(Botan::TLS::MAX_CIPHERTEXT_SIZE);
    // emit_data_buffer's size, also used as stat Indicator
    emit_buffer_index = 0;
}

void Callbacks::tls_emit_data(const uint8_t data[], size_t size) {
    memcpy(emit_data_buffer+emit_buffer_index, data, size);
    emit_buffer_index += (HsInt)size;
}   

void Callbacks::tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) {
    memcpy(record_received_buffer+record_buffer_index, data, size);
    record_buffer_index += (HsInt)size;
}
void Callbacks::tls_alert(Botan::TLS::Alert alert){
    if (alert.is_fatal()) {
        strcpy((char*)emit_data_buffer, alert.type_string().c_str());
        emit_buffer_index = HS_FATAL_ALERT;
    } else {
        emit_buffer_index = 0;
    }
}
bool Callbacks::tls_session_established(const Botan::TLS::Session& session) {
    emit_buffer_index = HS_SESSION_ESTABLISHED;
    return false;
}
Callbacks::~Callbacks(){
    free(emit_data_buffer);
    free(record_received_buffer);
}

////////////////////////////////////////////////////////////////////////////////

hs_credentials_t* new_credentials_t(
    const char* ca_store
#if __GLASGOW_HASKELL__ < 810
  , StgMutArrPtrs** cert_chain_files_arr
#else
  , StgArrBytes** cert_chain_files
#endif
  , const HsInt cert_chain_files_num
  , const char* key_file){
#if __GLASGOW_HASKELL__ < 810
    StgArrBytes** cert_chain_files = (StgArrBytes**)cert_chain_files_arr->payload;
#endif
    try {
        return new Credentials(ca_store, cert_chain_files, cert_chain_files_num, key_file);
    } catch (const std::exception &exc){
        return NULL;
    }
}

hs_credentials_t* free_credentials_t(credentials_t* cred){

}

botan_tls_client_t* new_tls_client(
        const char* serverinfo_hostname
    ,   const char* serverinfo_servicename
    ,   const uint16_t serverinfo_port 
    ,   const char* policy_type
    ,   const char* protocol_version
                                  ){

    Callbacks* callbacks = new Callbacks();
    Botan::AutoSeeded_RNG* rng = new Botan::AutoSeeded_RNG;
    Botan::TLS::Session_Manager_In_Memory* session_mgr= new Botan::TLS::Session_Manager_In_Memory(*rng);
    Client_Credentials* client_credentials = new Client_Credentials;
    Botan::TLS::Strict_Policy* policy = new Botan::TLS::Strict_Policy;
    // open the tls connection
    Botan::TLS::Client* tls_client = 
        new Botan::TLS::Client(*callbacks, *session_mgr, *client_credentials, *policy, *rng,
            Botan::TLS::Server_Information(serverinfo_hostname, serverinfo_servicename, serverinfo_port),
            Botan::TLS::Protocol_Version::TLS_V12);

    botan_tls_client_t* client = (botan_tls_client_t*)malloc(sizeof(botan_tls_client_t));
    client->tls_client = tls_client;
    client->callbacks = callbacks;
    client->rng = rng;
    client->session_mgr = session_mgr;
    client->client_credentials = client_credentials;
    client->policy = policy;

    return client;
}

void free_tls_client(botan_tls_client_t* client){
    client->callbacks->~Callbacks();
}

void hs_tls_received_data(botan_tls_client_t* client, const uint8_t buf[], size_t buf_size){
    try {
        client->tls_client->received_data(buf, buf_size);
    } catch (const std::exception &exc){
        strcpy(client->callbacks->emit_data_buffer, exc.what());
        client->callbacks->emit_buffer_index = HS_BOTAN_TLS_EXCEPTION;
    }
}

void hs_tls_send(botan_tls_client_t* client, const uint8_t buf[], size_t buf_size){
    try {
        client->tls_client->send(buf, buf_size);
    } catch (const std::exception &exc){
        strcpy(client->callbacks->emit_data_buffer, exc.what());
        client->callbacks->emit_buffer_index = HS_BOTAN_TLS_EXCEPTION;
    }
}
*/
