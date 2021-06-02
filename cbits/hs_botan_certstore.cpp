#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/internal/ffi_pkey.h>

#include <botan/x509cert.h>
#include <botan/x509path.h>
#include <botan/x509_crl.h>
#include <botan/certstor.h>
#include <botan/data_src.h>

#if defined(BOTAN_HAS_CERTSTOR_FLATFILE)
    #include <botan/certstor_flatfile.h>
#endif

#if defined(BOTAN_HAS_CERTSTOR_MACOS)
    #include <botan/certstor_macos.h>
#elif defined(BOTAN_HAS_CERTSTOR_WINDOWS)
    #include <botan/certstor_windows.h>
#endif
#include <HsFFI.h>
#include <string.h>

extern "C" {

using namespace Botan_FFI;

// Cert Store

BOTAN_FFI_DECLARE_STRUCT(botan_x509_certstore_struct, Botan::Certificate_Store, 0x8BD3442A);

typedef struct botan_x509_certstore_struct* botan_x509_certstore_t;

int botan_x509_certstore_load_file(botan_x509_certstore_t* certstore_obj, const char* certstore_path)
    {
    if(!certstore_obj || !certstore_path)
        return BOTAN_FFI_ERROR_NULL_POINTER;

#if defined(BOTAN_HAS_CERTSTOR_FLATFILE)

    return ffi_guard_thunk(__func__, [=]() -> int {
        std::unique_ptr<Botan::Certificate_Store> c(new Botan::Flatfile_Certificate_Store(certstore_path));
        *certstore_obj = new botan_x509_certstore_struct(c.release());
        return BOTAN_FFI_SUCCESS;
        });

#else
    return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
    }

int botan_x509_certstore_load_system(botan_x509_certstore_t* certstore_obj)
    {
    if(!certstore_obj)
        return BOTAN_FFI_ERROR_NULL_POINTER;


    return ffi_guard_thunk(__func__, [=]() -> int {
#if defined(BOTAN_HAS_CERTSTOR_MACOS)
        std::unique_ptr<Botan::Certificate_Store> c(new Botan::Certificate_Store_MacOS);
#elif defined(BOTAN_HAS_CERTSTOR_WINDOWS)
        std::unique_ptr<Botan::Certificate_Store> c(new Botan::Certificate_Store_Windows);
#elif defined(BOTAN_HAS_CERTSTOR_FLATFILE) && defined(BOTAN_SYSTEM_CERT_BUNDLE)
        std::unique_ptr<Botan::Certificate_Store> c(
             new Botan::Flatfile_Certificate_Store(BOTAN_SYSTEM_CERT_BUNDLE, true));
#else
        return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
        *certstore_obj = new botan_x509_certstore_struct(c.release());
        return BOTAN_FFI_SUCCESS;
        });

    }

int botan_x509_certstore_destroy(botan_x509_certstore_t certstore)
    {
    return BOTAN_FFI_CHECKED_DELETE(certstore);
    }

int botan_x509_cert_verify_with_certstore_crl(
    int* result_code,
    botan_x509_cert_t cert,
    const botan_x509_cert_t* intermediates,
    size_t intermediates_len,
    const botan_x509_certstore_t store,
    const botan_x509_crl_t* crls,
    size_t crls_len,
    size_t required_strength,
    const char* hostname_cstr,
    uint64_t reference_time)
    {
    if(required_strength == 0)
        required_strength = 110;

    return ffi_guard_thunk(__func__, [=]() -> int {
        const std::string hostname((hostname_cstr == nullptr) ? "" : hostname_cstr);
        const Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;
        const auto validation_time = reference_time == 0 ?
            std::chrono::system_clock::now() :
            std::chrono::system_clock::from_time_t(static_cast<time_t>(reference_time));

        std::vector<Botan::X509_Certificate> end_certs;
        end_certs.push_back(safe_get((Botan_FFI::botan_struct<Botan::X509_Certificate, 0x8F628937>*)cert));
        for(size_t i = 0; i != intermediates_len; ++i)
            end_certs.push_back(safe_get((Botan_FFI::botan_struct<Botan::X509_Certificate, 0x8F628937>*)intermediates[i]));

        std::vector<Botan::Certificate_Store*> trusted_roots;
        std::unique_ptr<Botan::Certificate_Store_In_Memory> trusted_crls;
        trusted_roots.push_back(&safe_get(store));

        if(crls_len > 0)
            {
            trusted_crls.reset(new Botan::Certificate_Store_In_Memory);
            for(size_t i = 0; i != crls_len; ++i)
                {
                trusted_crls->add_crl(safe_get((Botan_FFI::botan_struct<Botan::X509_CRL, 0x2C628910>*)crls[i]));
                }
            trusted_roots.push_back(trusted_crls.get());
            }

        Botan::Path_Validation_Restrictions restrictions(false, required_strength);

        auto validation_result = Botan::x509_path_validate(end_certs,
                                                                            restrictions,
                                                                            trusted_roots,
                                                                            hostname,
                                                                            usage,
                                                                            validation_time);

        if(result_code)
            *result_code = static_cast<int>(validation_result.result());

        if(validation_result.successful_validation())
            return 0;
        else
            return 1;
        });
    }

int hs_botan_x509_cert_verify_with_certstore_crl(
    botan_x509_cert_t cert,
    const botan_x509_cert_t* intermediates, HsInt intermediates_len,
    const botan_x509_certstore_t store,
    const botan_x509_crl_t* crls, HsInt crls_len,
    size_t required_strength,
    const char* hostname,
    uint64_t reference_time) {
     int r1;
     int r2 = botan_x509_cert_verify_with_certstore_crl(&r1, cert
                , intermediates, intermediates_len
                , store
                , crls, crls_len
                , required_strength, hostname, reference_time);
     if (r2 < 0){
          return r2;
     } else { 
          return r1; 
     }

    }

}
