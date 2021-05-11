#include <HsFFI.h>
#include <botan/ffi.h>

// Utility Functions
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
HsInt hs_botan_cipher_update(botan_cipher_t cipher_obj,
                               uint8_t* output,
                               const uint8_t* input,
                               HsInt input_off,
                               HsInt input_len);
// output buffer length should be at least equal to following call's result
// botan_cipher_output_length(cipher, input_length, &output_length)
// output_written may differ
HsInt hs_botan_cipher_finish(botan_cipher_t cipher_obj,
                           uint8_t* output,
                           HsInt output_len,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len);

// Multiple Precision Integers

int hs_botan_mp_to_hex(botan_mp_t mp, char *out, HsInt off);
HsInt hs_botan_mp_to_dec(botan_mp_t mp, char *out, HsInt off);
int hs_botan_mp_set_from_hex(botan_mp_t dest, const char *str, HsInt off, HsInt len);
int hs_botan_mp_set_from_dec(botan_mp_t dest, const char *str, HsInt off, HsInt len);
int hs_botan_mp_from_bin(botan_mp_t mp, const uint8_t* vec, HsInt off, HsInt len);
int hs_botan_mp_to_bin(botan_mp_t mp, uint8_t* vec, HsInt off);

// KDF & PBKDF
int hs_botan_kdf(const char* algo
                ,uint8_t out[], HsInt out_len
                ,const uint8_t passwd[], HsInt passwd_off, HsInt passwd_len
                ,const uint8_t salt[], HsInt salt_off, HsInt salt_len
                ,const uint8_t label[], HsInt label_off, HsInt label_len);

int hs_botan_pwdhash(const char* algo
                    ,HsInt p1, HsInt p2, HsInt p3
                    ,uint8_t out[], HsInt out_len
                    ,const char* passwd, HsInt passwd_len
                    ,const uint8_t salt[], HsInt salt_off, HsInt salt_len);
int hs_botan_pwdhash_timed(const char* algo
                          ,uint32_t msec
                          ,uint8_t out[], HsInt out_len
                          ,const char* passwd, HsInt passwd_len
                          ,const uint8_t salt[], HsInt salt_off, HsInt salt_len);

HsInt hs_botan_bcrypt_generate(uint8_t *out, const char *pwd, HsInt pwd_off, HsInt pwd_len
    , botan_rng_t rng, HsInt work_factor, uint32_t flags);
int hs_botan_bcrypt_is_valid(const char* pwd, HsInt pwd_off, HsInt pwd_len
    , const char* hash, HsInt hash_off, HsInt hash_len);

// MAC

int hs_botan_mac_set_key(botan_mac_t mac, const uint8_t* key, HsInt key_off, HsInt key_len);
int hs_botan_mac_update(botan_mac_t mac, const uint8_t* buf, HsInt off, HsInt len);
int hs_botan_mac_final(botan_mac_t mac, uint8_t out[]);
int hs_botan_mac_clear(botan_mac_t mac);
int hs_botan_mac_name(botan_mac_t mac, char* name, size_t* name_len);
int hs_botan_mac_get_keyspec(botan_mac_t mac,
    size_t* out_minimum_keylength,
    size_t* out_maximum_keylength,
    size_t* out_keylength_modulo);

// Public Key Creation, Import and Export
int hs_botan_privkey_load (botan_privkey_t* key, botan_rng_t rng
                          ,const uint8_t bits[], HsInt off, HsInt len
                          ,const char* passwd);
int hs_botan_pubkey_load (botan_pubkey_t* key
                         ,const uint8_t bits[], HsInt off, HsInt len);
// Public Key Encryption/Decryption
//
int hs_botan_pk_op_encrypt(botan_pk_op_encrypt_t op, botan_rng_t rng, uint8_t out[], HsInt *out_len, const uint8_t plaintext[], HsInt plaintext_off, HsInt plaintext_len);
int hs_botan_pk_op_decrypt(botan_pk_op_decrypt_t op, uint8_t out[], HsInt *out_len, uint8_t ciphertext[], HsInt ciphertext_off, HsInt ciphertext_len);

// Signature Generation & Signature Verification
//
int hs_botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t * in, HsInt off , HsInt len);
int hs_botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t * in, HsInt off, HsInt in_len);
int hs_botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t * sig, HsInt off, HsInt sig_len);

// Key Agreement

int hs_botan_pk_op_key_agreement(botan_pk_op_ka_t op, uint8_t out[], HsInt *out_len, const uint8_t other_key[], HsInt other_key_off, HsInt other_key_len, const uint8_t salt[], HsInt salt_off, HsInt salt_len);

// X.509 Certificates & X.509 Certificate Revocation Lists

int hs_botan_x509_cert_load(botan_x509_cert_t *cert_obj, const uint8_t cert[], HsInt cert_off, HsInt cert_len);
int hs_botan_x509_cert_verify(botan_x509_cert_t cert
        , const botan_x509_cert_t *intermediates, HsInt intermediates_len
        , const botan_x509_cert_t *trusted, HsInt trusted_len
        , HsInt required_strength, const char *hostname, uint64_t reference_time);
int hs_botan_x509_cert_verify_with_crl(botan_x509_cert_t cert
        , const botan_x509_cert_t *intermediates, HsInt intermediates_len
        , const botan_x509_cert_t *trusted, HsInt trusted_len
        , const botan_x509_crl_t *crls, HsInt crls_len
        , HsInt required_strength, const char *hostname, uint64_t reference_time);
int hs_botan_x509_cert_verify_with_certstore_crl(
   botan_x509_cert_t cert,
   const botan_x509_cert_t* intermediates, HsInt intermediates_len,
   const botan_x509_certstore_t store,
   const botan_x509_crl_t* crls, HsInt crls_len,
   size_t required_strength,
   const char* hostname_cstr,
   uint64_t reference_time);

// Key wrap

int hs_botan_key_wrap3394(const uint8_t key[], HsInt key_off, HsInt key_len
                         ,const uint8_t kek[], HsInt kek_off, HsInt kek_len
                         ,uint8_t wrapped_key[], size_t *wrapped_key_len);

int hs_botan_key_unwrap3394(const uint8_t wrapped_key[], HsInt wrapped_key_off, HsInt wrapped_key_len
                           ,const uint8_t kek[], HsInt kek_off, HsInt kek_len
                           ,uint8_t key[], size_t *key_len);
// OTP
int hs_botan_hotp_init(botan_hotp_t* hotp
                      ,const uint8_t key[], HsInt key_off, HsInt key_len
                      ,const char* hash_algo
                      ,HsInt digits);

int hs_botan_totp_init(botan_totp_t* totp
                      ,const uint8_t key[], HsInt key_off, HsInt key_len
                      ,const char* hash_algo
                      ,HsInt digits
                      ,HsInt time_step);
