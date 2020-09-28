#include <botan.h>
#include <botan/tls_client.h>


extern "C" {

typedef Botan::TLS::Client botan_tls_client_t;

botan_tls_client_t* new_tls_client();

}
