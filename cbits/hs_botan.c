#include <hs_botan.h>
#include <string.h>

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

HsInt hs_botan_cipher_update(botan_cipher_t cipher,
                           uint8_t* output,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len){
    size_t input_consumed, output_written;
    int r = botan_cipher_update(cipher, 0, output, input_len
        , &output_written, input+input_off, input_len, &input_consumed);
    if (r < 0){
        return (HsInt)r;
    } else {
        return (HsInt)output_written;
    }
}

HsInt hs_botan_cipher_finish(botan_cipher_t cipher,
                           uint8_t* output,
                           HsInt output_len,
                           const uint8_t* input,
                           HsInt input_off,
                           HsInt input_len){
    size_t input_consumed, output_written;
    int r = botan_cipher_update(cipher, BOTAN_CIPHER_UPDATE_FLAG_FINAL, output, output_len
        , &output_written, input+input_off, input_len, &input_consumed);
    if (r < 0){
        return (HsInt)r;
    } else {
        return (HsInt)output_written;
    }
}

// Multiple Precision Integers
int hs_botan_mp_to_hex(botan_mp_t mp, char *out, HsInt off){
    return botan_mp_to_hex(mp, out+off);
}
HsInt hs_botan_mp_to_dec(botan_mp_t mp, char *out, HsInt off){
    size_t len;
    int r = botan_mp_to_str(mp, 10, out+off, &len);
    if (r >= 0) {
        return (HsInt)len+off-1;
    } else {
        return (HsInt)r;
    }
}
int hs_botan_mp_set_from_hex(botan_mp_t dest, const char *str, HsInt off, HsInt len){
    char temp[len+3];
    temp[0] = '0';
    temp[1] = 'x';
    memcpy(temp+2, str+off, len);
    temp[len+2] = 0;
    return botan_mp_set_from_str(dest, temp);

}
int hs_botan_mp_set_from_dec(botan_mp_t dest, const char *str, HsInt off, HsInt len){
    char temp[len+1];
    memcpy(temp, str+off, len);
    temp[len] = 0;
    return botan_mp_set_from_str(dest, temp);
}
int hs_botan_mp_from_bin(botan_mp_t mp, const uint8_t* vec, HsInt off, HsInt len){
    return botan_mp_from_bin(mp, vec+off, len);
}
int hs_botan_mp_to_bin(botan_mp_t mp, uint8_t* vec, HsInt off){
    return botan_mp_to_bin(mp, vec+off);
}

// KDF & PBKDF

int hs_botan_kdf(const char* algo
                ,uint8_t out[], HsInt out_len
                ,const uint8_t passwd[], HsInt passwd_off, HsInt passwd_len
                ,const uint8_t salt[], HsInt salt_off, HsInt salt_len
                ,const uint8_t label[], HsInt label_off, HsInt label_len){
    return botan_kdf(algo, out, out_len, passwd+passwd_off, passwd_len, salt+salt_off, salt_len, label+label_off, label_len);
}

int hs_botan_pwdhash(const char* algo
                    ,HsInt p1, HsInt p2, HsInt p3
                    ,uint8_t out[], HsInt out_len
                    ,const char* passwd, HsInt passwd_off, HsInt passwd_len
                    ,const uint8_t salt[], HsInt salt_off, HsInt salt_len){
    return botan_pwdhash(algo, p1, p2, p3, out, out_len, passwd+passwd_off, passwd_len, salt+salt_off, salt_len);
}

int hs_botan_pwdhash_timed(const char* algo
                          ,uint32_t msec
                          ,uint8_t out[], HsInt out_len
                          ,const char* passwd, HsInt passwd_off, HsInt passwd_len
                          ,const uint8_t salt[], HsInt salt_off, HsInt salt_len){
    return botan_pwdhash_timed(algo, msec, NULL, NULL, NULL, out, out_len, passwd+passwd_off, passwd_len, salt+salt_off, salt_len);
}

// MAC

int hs_botan_mac_set_key(botan_mac_t mac, const uint8_t* key, HsInt key_off, HsInt key_len){
    return botan_mac_set_key(mac, key+key_off, key_len);
}
int hs_botan_mac_update(botan_mac_t mac, const uint8_t* buf, HsInt off ,HsInt len){
    return botan_mac_update(mac, buf + off, len);
}

int hs_botan_mac_final(botan_mac_t mac, uint8_t out[]){
    return botan_mac_final(mac, out);
}
int hs_botan_mac_clear(botan_mac_t mac){
    return botan_mac_clear(mac);
}

int hs_botan_mac_name(botan_mac_t mac, char* name, size_t* name_len){
    return botan_mac_name(mac, name, name_len);
}
int hs_botan_mac_get_keyspec(botan_mac_t mac,
    size_t* out_minimum_keylength,
    size_t* out_maximum_keylength,
    size_t* out_keylength_modulo){
        return botan_mac_get_keyspec(mac, out_minimum_keylength, out_maximum_keylength, out_keylength_modulo);
}

int hs_botan_mac_destroy(botan_mac_t mac){
    return botan_mac_destroy(mac);
}

// Public Key Creation, Import and Export

int hs_botan_privkey_load (botan_privkey_t* key, botan_rng_t rng
                          ,const uint8_t bits[], HsInt off, HsInt len
                          ,const char* passwd){
    if (*passwd == '\0') passwd = NULL;
    return botan_privkey_load(key, rng, bits+off, len, passwd);
}

int hs_botan_pubkey_load (botan_pubkey_t* key
                         ,const uint8_t bits[], HsInt off, HsInt len){
    return botan_pubkey_load(key, bits+off, len);
}

// Public Key Encryption / Decryption

int hs_botan_pk_op_encrypt(botan_pk_op_encrypt_t op, botan_rng_t rng, uint8_t out[], HsInt *out_len, const uint8_t plaintext[], HsInt plaintext_off, HsInt plaintext_len){
    return botan_pk_op_encrypt(op, rng, out, out_len, plaintext+plaintext_off, plaintext_len);
}

int hs_botan_pk_op_decrypt(botan_pk_op_decrypt_t op, uint8_t out[], HsInt *out_len, uint8_t ciphertext[], HsInt ciphertext_off, HsInt ciphertext_len){
    return botan_pk_op_decrypt(op, out, out_len, ciphertext+ciphertext_off, ciphertext_len);
}

// Signature Generation

int hs_botan_pk_op_sign_update(botan_pk_op_sign_t op, const uint8_t in[], HsInt off, HsInt len){
    return botan_pk_op_sign_update(op, in+off, len);
}

// Signature Verification

int hs_botan_pk_op_verify_update(botan_pk_op_verify_t op, const uint8_t in[], HsInt off, HsInt len){
    return botan_pk_op_verify_update(op, in+off, len);
}

int hs_botan_pk_op_verify_finish(botan_pk_op_verify_t op, const uint8_t sig[], HsInt off, HsInt len){
    return botan_pk_op_verify_finish(op, sig+off, len);
}

// Key Agreement

int hs_botan_pk_op_key_agreement(botan_pk_op_ka_t op, uint8_t out[], HsInt *out_len, const uint8_t other_key[], HsInt other_key_off, HsInt other_key_len, const uint8_t salt[], HsInt salt_off, HsInt salt_len){
    return botan_pk_op_key_agreement(op, out, out_len, other_key+other_key_off, other_key_len, salt+salt_off, salt_len);
}

/*
int hs_botan_mceies_encrypt(botan_pubkey_t mce_key, botan_rng_t rng, const char *aead, const uint8_t pt[], HsInt pt_off, HsInt pt_len, const uint8_t ad[], HsInt ad_off, HsInt ad_len, uint8_t ct[], HsInt *ct_len){
    return botan_mceies_encrypt(mce_key, rng, aead, pt+pt_off, pt_len, ad+ad_off, ad_len, ct, ct_len);
}
*/
