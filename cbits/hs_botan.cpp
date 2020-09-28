#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <hs_botan.h>

class Callbacks : public Botan::TLS::Callbacks
{
   public:
      // could be called both during received_data or send
      void tls_emit_data(const uint8_t data[], size_t size) override {
         }

      // could be called both during received_data
      void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override {
         }

      void tls_alert(Botan::TLS::Alert alert) override {
         }

     // the session with the tls server was established
     // return false to prevent the session from being cached, true to
     // cache the session in the configured session manager
      bool tls_session_established(const Botan::TLS::Session& session) override {


         return false;
        }
    private:
      char* emit_data_buffer;
      char* record_received_buffer;
      
};

class Client_Credentials : public Botan::Credentials_Manager
   {
   public:
      Client_Credentials()
         {
         // Here we base trust on the system managed trusted CA list
         //m_stores.push_back(new Botan::System_Certificate_Store);
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

botan_tls_client_t* new_tls_client(){
   Callbacks callbacks;
   Botan::AutoSeeded_RNG rng;
   Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
   Client_Credentials creds;
   Botan::TLS::Strict_Policy policy;

   // open the tls connection
   Botan::TLS::Client client(callbacks,
                             session_mgr,
                             creds,
                             policy,
                             rng,
                             Botan::TLS::Server_Information("botan.randombit.net", 443),
                             Botan::TLS::Protocol_Version::TLS_V12);
   return &client;
}

