#include <botan.h>
#include <HsFFI.h>
#include <botan/certstor_system.h>
#include <botan/tls_client.h>

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

class Client_Credentials : public Botan::Credentials_Manager
   {
   public:
      Client_Credentials()
         {
         // Here we base trust on the system managed trusted CA list
         m_stores.push_back(new Botan::System_Certificate_Store);
         }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
         const std::string& type,
         const std::string& context) override
         {
         // return a list of certificates of CAs we trust for tls server certificates
         // ownership of the pointers remains with Credentials_Manager
         return m_stores;
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context) override
         {
         // when using tls client authentication (optional), return
         // a certificate chain being sent to the tls server,
         // else an empty list
         return std::vector<Botan::X509_Certificate>();
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
         const std::string& type,
         const std::string& context) override
         {
         // when returning a chain in cert_chain(), return the private key
         // associated with the leaf certificate here
         return nullptr;
         }

   private:
       std::vector<Botan::Certificate_Store*> m_stores;
};


extern "C" {

#define HS_MAX_CIPHERTEXT_SIZE Botan::TLS::MAX_CIPHERTEXT_SIZE
#define HS_SESSION_ESTABLISHED -1
#define HS_FATAL_ALERT -2
#define HS_BOTAN_TLS_EXCEPTION -3

typedef Callbacks                   botan_callbacks_t;
typedef struct {
    Botan::TLS::Client*             tls_client;
    Callbacks*                      callbacks;
    Client_Credentials*             client_credentials;
    Botan::RandomNumberGenerator*   rng;
    Botan::TLS::Session_Manager*    session_mgr;
    Botan::TLS::Policy*             policy;
} botan_tls_client_t;


botan_tls_client_t* new_tls_client();
void free_tls_client(botan_tls_client_t* client);
void hs_tls_received_data(botan_tls_client_t* client, const uint8_t buf[], size_t buf_size);
void hs_tls_send(botan_tls_client_t* client, const uint8_t buf[], size_t buf_size);

    
}

#endif 
