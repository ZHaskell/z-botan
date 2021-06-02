#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/stream_cipher.h>
#include <HsFFI.h>
#include <string.h>

extern "C" {

using namespace Botan_FFI;

// Stream cipher

BOTAN_FFI_DECLARE_STRUCT(botan_stream_cipher_struct, Botan::StreamCipher, 0x9F5B7D34);

typedef struct botan_stream_cipher_struct* botan_stream_cipher_t;

int botan_stream_cipher_init(botan_stream_cipher_t* stream_cipher, const char* stream_cipher_name)
    {
    return ffi_guard_thunk(__func__, [=]() -> int {
        if(stream_cipher == nullptr || stream_cipher_name == nullptr || *stream_cipher_name == 0)
            return BOTAN_FFI_ERROR_NULL_POINTER;

        std::unique_ptr<Botan::StreamCipher> s = Botan::StreamCipher::create(stream_cipher_name);
        if(s == nullptr)
            return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;

        *stream_cipher = new botan_stream_cipher_struct(s.release());
        return BOTAN_FFI_SUCCESS;
        });
    }

int botan_stream_cipher_destroy(botan_stream_cipher_t stream_cipher)
    {
    return BOTAN_FFI_CHECKED_DELETE(stream_cipher);
    }


int botan_stream_cipher_seek(botan_stream_cipher_t stream_cipher, size_t offset)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { c.seek(offset); });
    }


int botan_stream_cipher_clear(botan_stream_cipher_t stream_cipher)
   {
   return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { c.clear(); });
   }

int botan_stream_cipher_query_keylen(botan_stream_cipher_t stream_cipher,
                                        size_t* out_minimum_keylength,
                                        size_t* out_maximum_keylength)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, {
        *out_minimum_keylength = c.key_spec().minimum_keylength();
        *out_maximum_keylength = c.key_spec().maximum_keylength();
        });
    }

int botan_stream_cipher_get_keyspec(botan_stream_cipher_t stream_cipher,
                                      size_t* out_minimum_keylength,
                                      size_t* out_maximum_keylength,
                                      size_t* out_keylength_modulo)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, {
        if(out_minimum_keylength)
            *out_minimum_keylength = c.key_spec().minimum_keylength();
        if(out_maximum_keylength)
            *out_maximum_keylength = c.key_spec().maximum_keylength();
        if(out_keylength_modulo)
            *out_keylength_modulo = c.key_spec().keylength_multiple();
        });
    }

int botan_stream_cipher_set_key(botan_stream_cipher_t stream_cipher,
                                 const uint8_t* key, size_t key_len)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { c.set_key(key, key_len); });
    }

int botan_stream_cipher_set_iv(botan_stream_cipher_t stream_cipher,
                                 const uint8_t* iv, size_t iv_len)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { c.set_iv(iv, iv_len); });
    }

int hs_botan_stream_cipher_set_iv(botan_stream_cipher_t stream_cipher,
                              const uint8_t* iv, HsInt off, HsInt iv_len)
    {
    return botan_stream_cipher_set_iv(stream_cipher, iv+off, iv_len);
    }

int botan_stream_cipher_cipher(botan_stream_cipher_t stream_cipher,
                                const uint8_t input[],
                                uint8_t output[],
                                size_t len)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { c.cipher(input, output, len); });
    }


int hs_botan_stream_cipher_cipher(botan_stream_cipher_t stream_cipher,
                                uint8_t output[],
                                const uint8_t input[],
                                HsInt off,
                                HsInt len)
    {
    return botan_stream_cipher_cipher(stream_cipher, input+off, output, len);
    }

int botan_stream_cipher_write_keystream(botan_stream_cipher_t stream_cipher,
                                uint8_t output[],
                                size_t len)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { c.write_keystream(output, len); });
    }

int botan_stream_cipher_valid_iv_length(botan_stream_cipher_t stream_cipher, size_t nl)
    {
    return BOTAN_FFI_RETURNING(Botan::StreamCipher, stream_cipher, c, {
        return c.valid_iv_length(nl) ? 1 : 0;
        });
    }

int botan_stream_cipher_get_default_iv_length(botan_stream_cipher_t stream_cipher, size_t* nl)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, { *nl = c.default_iv_length(); });
    }

int botan_stream_cipher_name(botan_stream_cipher_t stream_cipher, char* name, size_t* name_len)
    {
    return BOTAN_FFI_DO(Botan::StreamCipher, stream_cipher, c, {
        return write_str_output(name, name_len, c.name()); });
    }

}
