#include "crypto.hpp"

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <stdexcept>

#include "client.hpp"
#include "connection.hpp"
#include "context.hpp"
#include "endpoint.hpp"
#include "server.hpp"

#define CHECK(x)                                                     \
    if (x < 0)                                                       \
    {                                                                \
        log::trace(log_cat, "Function call to {} failed", __func__); \
    }

#define ALPN "h2"

namespace oxen::quic
{
    static const gnutls_datum_t alpn = {(uint8_t*)ALPN, sizeof(ALPN) - 1};

    extern "C"
    {
        int server_cb_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* ms)
        {
            auto conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            auto server = static_cast<Connection*>(conn_ref->user_data)->server();

            if (!server)
            {
                log::warning(log_cat, "Error: server unsuccessfully retrieved from conn_ref->user_data->server()");
                return -1;
            }

            return server->context->server_tls_cb(session, htype, when, incoming, ms);
        }

        int client_cb_wrapper(
                gnutls_session_t session,
                unsigned int htype,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            const auto& conn_ref = static_cast<ngtcp2_crypto_conn_ref*>(gnutls_session_get_ptr(session));
            const auto& client = static_cast<Connection*>(conn_ref->user_data)->client();

            if (!client)
            {
                log::warning(log_cat, "Error: client unsuccessfully retrieved from conn_ref->user_data->client()");
                return -1;
            }

            auto gtls_ctx = std::dynamic_pointer_cast<GNUTLSContext>(client->context->tls_ctx);

            return gtls_ctx->client_tls_cb(session, htype, when, incoming, msg);
        }

        int server_protocol_hook(
                gnutls_session_t session,
                unsigned int type,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            assert(type == GNUTLS_HANDSHAKE_CLIENT_HELLO);
            assert(when == GNUTLS_HOOK_POST);
            assert(incoming != 0);

            gnutls_datum_t _alpn;

            // confirm ALPN extension
            CHECK(gnutls_alpn_get_selected_protocol(session, &_alpn));

            // set protocol
            CHECK(gnutls_alpn_set_protocols(session, &_alpn, 1, 0));

            return 0;
        }

        int client_verification_hook(
                gnutls_session_t session,
                unsigned int type,
                unsigned int when,
                unsigned int incoming,
                const gnutls_datum_t* msg)
        {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
            return 0;
        }
    }

    GNUTLSContext::~GNUTLSContext()
    {
        gnutls_certificate_free_credentials(cred);

        gnutls_deinit(session);
    }

    // The session pointer to the conn_ref struct needs to be done at Connection creation, so
    // conn_link will likely need to stay a separate function, especially for server connections
    // created in Server::accept_initial_connection
    // int GNUTLSContext::conn_link(Connection& conn)
    // {
    //     gnutls_session_set_ptr(session, &conn.tls_context->conn_ref);
    //     return 0;
    // }

    int GNUTLSContext::client_init(GNUTLSCert& cert)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
            log::warning(log_cat, "Client gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));

        config_client_certs(cert);

        if (auto rv = gnutls_init(&session, GNUTLS_CLIENT); rv < 0)
            log::warning(log_cat, "Client gnutls_init failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_set_default_priority(session); rv < 0)
            log::warning(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));

        if (client_tls_cb)
        {
            log::warning(log_cat, "Emplacing client tls callback in hook function...");
            gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, client_cb_wrapper);
        }

        if (auto rv = ngtcp2_crypto_gnutls_configure_client_session(session); rv < 0)
            log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_client_session failed: {}", ngtcp2_strerror(rv));
        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred); rv < 0)
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            log::warning(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));

        // NOTE: IPv4 or IPv6 addresses not allowed (cannot be "127.0.0.1")
        if (auto rv = gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost")); rv < 0)
            log::warning(log_cat, "gnutls_server_name_set failed: {}", gnutls_strerror(rv));

        log::info(log_cat, "Completed client_init");
        return 0;
    }

    int GNUTLSContext::server_init(GNUTLSCert& cert)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto rv = gnutls_certificate_allocate_credentials(&cred); rv < 0)
            log::warning(log_cat, "Server gnutls_certificate_allocate_credentials failed: {}", gnutls_strerror(rv));

        config_server_certs(cert);

        if (auto rv = gnutls_init(&session, GNUTLS_SERVER); rv < 0)
            log::warning(log_cat, "Server gnutls_init failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_set_default_priority(session); rv < 0)
            log::warning(log_cat, "gnutls_set_default_priority failed: {}", gnutls_strerror(rv));

        // uncomment after testing server callbacks
        //
        // gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_CLIENT_HELLO,
        // GNUTLS_HOOK_POST, server_protocol_hook);

        // fix this so it is like the client hook
        if (cert.server_tls_cb)
            gnutls_handshake_set_hook_function(session, GNUTLS_HANDSHAKE_FINISHED, GNUTLS_HOOK_POST, server_cb_wrapper);

        if (auto rv = ngtcp2_crypto_gnutls_configure_server_session(session); rv < 0)
            log::warning(log_cat, "ngtcp2_crypto_gnutls_configure_server_session failed: {}", ngtcp2_strerror(rv));

        gnutls_session_set_ptr(session, &conn_ref);

        if (auto rv = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred); rv < 0)
            log::warning(log_cat, "gnutls_credentials_set failed: {}", gnutls_strerror(rv));

        if (auto rv = gnutls_alpn_set_protocols(session, &alpn, 1, GNUTLS_ALPN_MANDATORY); rv < 0)
            log::warning(log_cat, "gnutls_alpn_set_protocols failed: {}", gnutls_strerror(rv));

        log::info(log_cat, "Completed server_init");
        return 0;
    }

    int GNUTLSContext::config_server_certs(GNUTLSCert& cert)
    {
        if (auto rv = gnutls_certificate_set_x509_system_trust(cred); rv < 0)
            log::warning(log_cat, "Set x509 system trust failed with code {}", gnutls_strerror(rv));

        if (!cert.remotecafile.empty())
        {
            if (auto rv = gnutls_certificate_set_x509_trust_file(cred, cert.remotecafile.c_str(), cert.remoteca_type);
                rv < 0)
                log::warning(log_cat, "Set x509 trust file failed with code {}", gnutls_strerror(rv));
        }

        if (auto rv = gnutls_certificate_set_x509_key_file(cred, cert.certfile.c_str(), cert.keyfile.c_str(), cert.key_type);
            rv < 0)
            log::warning(log_cat, "Set x509 key file failed with code {}", gnutls_strerror(rv));

        return 0;
    }

    int GNUTLSContext::config_client_certs(GNUTLSCert& cert)
    {
        if (auto rv = gnutls_certificate_set_x509_system_trust(cred); rv < 0)
            log::warning(log_cat, "Set x509 system trust failed with code {}", gnutls_strerror(rv));

        // remote CA file is passed, but not remote cert file
        if (!cert.remotecafile.empty() && cert.remotecert.empty())
        {
            if (auto rv = gnutls_certificate_set_x509_trust_file(cred, cert.remotecafile.c_str(), cert.remoteca_type);
                rv < 0)
                log::warning(log_cat, "Set x509 trust file failed with code {}", gnutls_strerror(rv));
        }
        // remote cert file is passed, but not remote CA file
        else if (cert.remotecafile.empty() && !cert.remotecert.empty())
        {
            if (auto rv = gnutls_certificate_set_x509_trust_file(cred, cert.remotecert.c_str(), cert.remotecert_type);
                rv < 0)
                log::warning(log_cat, "Set x509 trust file failed with code {}", gnutls_strerror(rv));
        }
        else
        {
            if (!cert.server_tls_cb)
                throw std::invalid_argument(
                        "Error. Either the remote CA, remote cert, or cert verification callback must be passed");
        }

        if (!cert.keyfile.empty() && !cert.certfile.empty())
        {
            if (auto rv = gnutls_certificate_set_x509_key_file(
                        cred, cert.certfile.c_str(), cert.keyfile.c_str(), cert.key_type);
                rv < 0)
                log::warning(log_cat, "Set x509 key file failed with code {}", gnutls_strerror(rv));
        }

        return 0;
    }

}  // namespace oxen::quic
