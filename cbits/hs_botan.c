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

int hs_botan_mac_init(botan_mac_t* mac, const char * mac_name, uint32_t flags){
    return botan_mac_init(mac, mac_name, flags);
}
int hs_botan_mac_output_length(botan_mac_t mac, size_t* output_length){
    return botan_mac_output_length(mac, output_length);
}

int hs_botan_mac_set_key(botan_mac_t mac, const uint8_t* key, HsInt key_len){
    return botan_mac_set_key(mac, key, key_len);
}
int hs_botan_mac_update(botan_mac_t mac, const uint8_t* buf, HsInt len){
    return botan_mac_update(mac,buf, len);
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
                                                     return botan_mac_get_key_spec(mac, out_minimum_keylength, out_maximum_keylength, out_keylength_modulo);
                                                 }

int hs_botan_mac_destroy(botan_mac_t mac){
    return botan_mac_destroy(mac);
}