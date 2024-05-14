#pragma once

#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <optional>
#include <variant>

#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    using namespace oxenc::literals;

    class Connection;

    const std::string translate_key_format(gnutls_x509_crt_fmt_t crt);

    const std::string translate_cert_type(gnutls_certificate_type_t type);

    const std::string get_cert_type(gnutls_session_t session, gnutls_ctype_target_t type);

    extern "C"
    {
        int cert_verify_callback_gnutls(gnutls_session_t g_session);

        void gnutls_log(int level, const char* str);

        struct gnutls_log_setter
        {
            gnutls_log_setter()
            {
                gnutls_global_set_log_level(99);
                gnutls_global_set_log_function(gnutls_log);
            }
        };
    }

    static gnutls_log_setter gnutls_logger{};

    namespace fs = std::filesystem;

    using gnutls_callback = std::function<int(
            gnutls_session_t session,
            unsigned int htype,
            unsigned int when,
            unsigned int incoming,
            const gnutls_datum_t* msg)>;

    inline constexpr size_t CERT_HEADER_SIZE = 12;
    inline constexpr size_t GNUTLS_KEY_SIZE = 32;  // for now, only supporting Ed25519 keys (32 bytes)
    inline constexpr size_t GNUTLS_SECRET_KEY_SIZE = 64;

    // These bytes mean "this is a raw Ed25519 private key" in ASN.1 (or something like that)
    inline constexpr auto ASN_ED25519_SEED_PREFIX = "302e020100300506032b657004220420"_hex;
    // These bytes mean "this is a raw Ed25519 public key" in ASN.1 (or something like that)
    inline constexpr auto ASN_ED25519_PUBKEY_PREFIX = "302a300506032b6570032100"_hex;

    struct gnutls_key
    {
      private:
        std::array<unsigned char, GNUTLS_KEY_SIZE> buf{};

        gnutls_key(const unsigned char* data, size_t size) { write(data, size); }

      public:
        gnutls_key() = default;
        gnutls_key(std::string_view data) : gnutls_key{convert_sv<unsigned char>(data)} {}
        gnutls_key(ustring_view data) : gnutls_key{data.data(), data.size()} {}

        //  Writes to the internal buffer holding the gnutls key
        void write(const unsigned char* data, size_t size)
        {
            if (size != GNUTLS_KEY_SIZE)
                throw std::invalid_argument{"GNUTLS key must be 32 bytes!"};

            std::memcpy(buf.data(), data, size);
        }

        ustring_view view() const { return {buf.data(), buf.size()}; }

        gnutls_key(const gnutls_key& other) { *this = other; }

        gnutls_key& operator=(const gnutls_key& other)
        {
            buf = other.buf;
            return *this;
        }

        void operator()(ustring_view data) { write(data.data(), data.size()); }

        explicit operator bool() const { return not buf.empty(); }

        bool operator==(const gnutls_key& other) const { return buf == other.buf; }
        bool operator!=(const gnutls_key& other) const { return !(*this == other); }
    };

    // key: remote key to verify, alpn: negotiated alpn's
    using key_verify_callback = std::function<bool(const ustring_view& key, const ustring_view& alpn)>;

    inline const gnutls_datum_t GNUTLS_DEFAULT_ALPN{
            const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(default_alpn_str.data())),
            static_cast<uint32_t>(default_alpn_str.size())};

    struct gnutls_callback_wrapper
    {
        gnutls_callback cb = nullptr;
        unsigned int htype = 20;
        unsigned int when = 1;
        unsigned int incoming = 0;

        bool applies(unsigned int h, unsigned int w, unsigned int i) const
        {
            return cb && htype == h && when == w && incoming == i;
        }

        operator bool() const { return cb != nullptr; }

        template <typename... Args>
        auto operator()(Args&&... args) const
        {
            return cb(std::forward<Args>(args)...);
        }
    };

    // Struct to wrap cert/key information. Can hold either a string-path, gnutls_datum of the
    // actual key or cert, plus extension and type info.
    // Passable as:
    //      - const char* (ex: to gnutls_certificate_set_x509_key_file)
    //      - gnutls_datum_t* (ex: to gnutls_certificate_set_x509_trust_dir)
    //      - gnutls_x509_crt_fmt_t (ex: to parameter 3 of the above functions)
    struct x509_loader
    {
        std::variant<std::string, fs::path> source;
        gnutls_datum_t mem{nullptr, 0};  // Will point at the string content when in_mem() is true
        gnutls_x509_crt_fmt_t format{};

        x509_loader() = default;
        x509_loader(std::string input)
        {
            if (auto path = fs::path(
#ifdef _WIN32
                        std::u8string{reinterpret_cast<char8_t*>(input.data()), input.size()}
#else
                        input
#endif
                );
                fs::exists(path))
            {
#ifdef _WIN32
                auto p8_str = path.extension().u8string();
                auto path_str = std::string{reinterpret_cast<const char*>(p8_str.data()), p8_str.size()};

                format = (str_tolower(path_str) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
#else
                format = (str_tolower(path.extension().string()) == ".pem") ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
#endif
                source = std::move(path);
            }
            else if (bool pem = input.starts_with("-----"); pem || (input.starts_with("\x30") && input.size() >= 48))
            {
                source = std::move(input);
                update_datum();
                format = pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER;
            }
            else
            {
                throw std::invalid_argument{"Invalid cert/key: input is neither a file nor raw valid x509 data"};
            }
        }

      private:
        void update_datum()
        {
            if (auto* s = std::get_if<std::string>(&source))
            {
                mem.data = reinterpret_cast<uint8_t*>(s->data());
                mem.size = s->size();
            }
            else
            {
                mem.data = nullptr;
                mem.size = 0;
            }
        }

      public:
        x509_loader(const x509_loader& other) { *this = other; }
        x509_loader& operator=(const x509_loader& other)
        {
            source = other.source;
            update_datum();
            format = other.format;
            return *this;
        }

        x509_loader(x509_loader&& other) { *this = std::move(other); }
        x509_loader& operator=(x509_loader&& other)
        {
            source = std::move(other.source);
            update_datum();
            format = std::move(other.format);
            return *this;
        }

        bool from_mem() const
        {
            auto* s = std::get_if<std::string>(&source);
            return s && !s->empty();
        }

        // returns true if we have either a non-empty path or non-empty raw cert data
        explicit operator bool() const
        {
            return std::visit([](const auto& x) { return !x.empty(); }, source);
        }

        // Implicit conversion to a `const gnutls_datum_t*`.  The datum will point at nullptr if
        // this is not a `from_mem()` instance.
        //
        // Hidden behind a template so that implicit conversion to pointer doesn't cause trouble via
        // other unwanted implicit conversions.
        template <typename T>
            requires std::same_as<T, gnutls_datum_t>
        operator const T*() const
        {
            return &mem;
        }

#ifdef _WIN32
      private:
        // On windows we can't return a c string directly from a path (because paths are
        // natively wchar_t-based), so we write the local utf8 path here first when path_cstr is
        // called.
        mutable std::string u8path_buf;

      public:
#endif

        // Implicit conversion to a C string (null terminated `const char*`) containing the path, if
        // this is not a `from_mem()` instance (otherwise returns an empty c string).
        //
        // Hidden behind a template so that implicit conversion to pointer doesn't cause trouble via
        // other unwanted implicit conversions.
        template <typename T>
            requires std::same_as<T, char>
        operator const T*() const
        {
            if (auto* p = std::get_if<fs::path>(&source))
            {
#ifdef _WIN32
                auto u8_path = p->u8string();
                u8path_buf = std::string{reinterpret_cast<const char*>(u8_path.data()), u8_path.size()};
                return u8path_buf.c_str();
#else
                return p->c_str();
#endif
            }
            return "";
        }
    };

    class GNUTLSCreds : public TLSCreds
    {
        friend class GNUTLSSession;

      private:
        // Construct from raw Ed25519 keys
        GNUTLSCreds(std::string_view ed_seed, std::string_view ed_pubkey);

      public:
        gnutls_pcert_st pcrt;
        gnutls_privkey_t pkey;

        ~GNUTLSCreds();

        const bool using_raw_pk{false};

        gnutls_certificate_credentials_t cred;
        gnutls_anon_client_credentials_t client_anon;
        gnutls_anon_server_credentials_t server_anon;

        key_verify_callback key_verify;

        gnutls_priority_t priority_cache;

        void load_keys(x509_loader& seed, x509_loader& pk);

        void set_key_verify_callback(key_verify_callback cb) { key_verify = std::move(cb); }

        static std::shared_ptr<GNUTLSCreds> make_from_ed_keys(std::string_view seed, std::string_view pubkey);

        static std::shared_ptr<GNUTLSCreds> make_from_ed_seckey(std::string_view sk);

        std::unique_ptr<TLSSession> make_session(Connection& c, const std::vector<ustring>& alpns) override;
    };

    class GNUTLSSession : public TLSSession
    {
      public:
        const GNUTLSCreds& creds;

      private:
        gnutls_session_t session;
        gnutls_datum_t session_ticket_key;
        gnutls_anti_replay_t anti_replay;

        bool is_client;

        gnutls_key _expected_remote_key{};

        gnutls_key _remote_key{};

      public:
        GNUTLSSession(
                GNUTLSCreds& creds,
                Connection& c,
                const std::vector<ustring>& alpns,
                std::optional<gnutls_key> expected_key = std::nullopt);

        ~GNUTLSSession();

        void* get_session() override { return session; }

        void* get_anti_replay() const override { return anti_replay; }

        const void* get_session_ticket_key() const override { return &session_ticket_key; }

        bool get_early_data_accepted() const override
        {
            return gnutls_session_get_flags(session) & GNUTLS_SFLAGS_EARLY_DATA;
        }

        ustring_view remote_key() const override { return _remote_key.view(); }

        ustring_view selected_alpn() override;

        bool validate_remote_key();

        int send_session_ticket() override;

        void set_expected_remote_key(ustring key) override { _expected_remote_key(key); }
    };

    GNUTLSSession* get_session_from_gnutls(gnutls_session_t g_session);
    Connection* get_connection_from_gnutls(gnutls_session_t g_session);

}  // namespace oxen::quic
