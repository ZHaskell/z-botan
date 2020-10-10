#include <botan/tls_client.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>
#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <hs_botan.h>
#include <iostream>


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

botan_tls_client_t* new_tls_client(

                                  ){

    Callbacks* callbacks = new Callbacks();
    Botan::AutoSeeded_RNG* rng = new Botan::AutoSeeded_RNG;
    Botan::TLS::Session_Manager_In_Memory* session_mgr= new Botan::TLS::Session_Manager_In_Memory(*rng);
    Client_Credentials* client_credentials = new Client_Credentials;
    Botan::TLS::Strict_Policy* policy = new Botan::TLS::Strict_Policy;
    // open the tls connection
    Botan::TLS::Client* tls_client = 
        new Botan::TLS::Client(*callbacks, *session_mgr, *client_credentials, *policy, *rng,
            Botan::TLS::Server_Information("www.bing.com", 443),
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
