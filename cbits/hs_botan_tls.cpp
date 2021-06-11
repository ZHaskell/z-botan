#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>

#include <botan/credentials_manager.h>
#include <botan/certstor.h>


#include <HsFFI.h>
#include <string.h>
#include <memory.h>

namespace Botan {

class Cred_Manager : public Botan::Credentials_Manager
    {
    private:
        struct cert_pair
        {
            std::vector<Botan::X509_Certificate> certs;
            Botan::Private_Key* key;
        };

        std::vector<cert_pair> creds;

        std::vector<Botan::Certificate_Store*> cert_store;

    public:
        Cred_Manager(Botan::Certificate_Store* cs, HsInt siz) {
            for (HsInt i = 0; i < siz; i++) {
                cert_store.push_back(&cs[i]);
            }
        }

        void add_cert_pair(Botan::Private_Key* key, Botan::X509_Certificate* cert_list, HsInt cert_siz){
            cert_pair cp;
            cp.key = key;
            for (HsInt i = 0; i < cert_siz; i++) {
                cp.certs.push_back(cert_list[i]);
            }
        }

        Botan::Private_Key *private_key_for(const Botan::X509_Certificate &cert,
                                            const std::string & /*type*/,
                                            const std::string & /*context*/) override
        {
            for (auto &&i : creds)
            {
                if (cert == i.certs[0])
                {
                    return i.key;
                }
            }
            return nullptr;
        }

        std::vector<Botan::X509_Certificate> cert_chain(const std::vector<std::string> &algos,
                                                        const std::string &type,
                                                        const std::string &hostname) override
        {
            BOTAN_UNUSED(type);

            for (auto &&i : creds)
            {
                if (std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end())
                {
                    continue;
                }

                if (hostname != "" && !i.certs[0].matches_dns_name(hostname))
                {
                    continue;
                }

                return i.certs;
            }

            return std::vector<Botan::X509_Certificate>();
        }

        std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(const std::string &type,
                                                                                const std::string & /*hostname*/) override
        {

            // don't ask for client certs
            if (type == "tls-server")
            {
                return {};
            } else {
                return cert_store;
            }
        }
    };
}

extern "C" {

using namespace Botan_FFI;

// Cert Store

BOTAN_FFI_DECLARE_STRUCT(botan_x509_cred_manager_struct, Botan::Cred_Manager, 0x0353d72a);

typedef struct botan_x509_cred_manager_struct* botan_x509_cred_manager_t;

int botan_x509_cred_manager_init()
    {
        return 0;
    }

int botan_x509_cred_manager_destroy(botan_x509_cred_manager_t cred_manager)
    {
    return BOTAN_FFI_CHECKED_DELETE(cred_manager);
    }

}
