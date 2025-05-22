#ifndef OPENSSLSTREEBOG512HMAC
#define OPENSSLSTREEBOG512HMAC

#include <openssl/evp.h>
#include <stdexcept>
#include "Hash.hpp"
#include "SecureBuffer.hpp"

template <size_t KeyLen>
class OpenSSLStreebog512HMAC : public MAC<64, 64, KeyLen> {
private:
    EVP_MAC_CTX *ctx_;
    EVP_MAC* mac_;
    SecureBuffer<KeyLen> key_;

    inline void free() noexcept { 
        if (ctx_) EVP_MAC_CTX_free(ctx_);
        if (mac_) EVP_MAC_free(mac_);
        ctx_ = nullptr;
        mac_ = nullptr;
    }
public:
    OpenSSLStreebog512HMAC() : ctx_(nullptr), mac_(nullptr) {}
    void initKeySchedule(const SecureBuffer<KeyLen> &key) override;
    inline OpenSSLStreebog512HMAC(const SecureBuffer<KeyLen> &key)
        { initKeySchedule(key); }
    void update(const uint8_t *data, const size_t size);
    inline void update(const std::vector<uint8_t> &data)
        { update(data.data(), data.size()); }
    std::vector<uint8_t> digest();
    void digest(uint8_t *digest_buffer);
    inline void clear() override { free(); initKeySchedule(key_); }
    inline ~OpenSSLStreebog512HMAC() noexcept { free(); }

    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 64;
    static constexpr size_t KeySize = KeyLen;
};

template <size_t KeyLen>
void OpenSSLStreebog512HMAC<KeyLen>::initKeySchedule(const SecureBuffer<KeyLen> &key) {
    key_ = key;
    mac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac_) throw std::runtime_error("Не удалось получить MAC HMAC.");
    ctx_ = EVP_MAC_CTX_new(mac_);
    if (!ctx_) {
        EVP_MAC_free(mac_);
        throw std::runtime_error("Не удалось создать MAC контекст.");
    }
    char digest_name[] = SN_id_GostR3411_2012_512;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", digest_name, 0),
        OSSL_PARAM_END
    };
    if (!EVP_MAC_init(ctx_, key_.raw(), KeyLen, params)) {
        EVP_MAC_CTX_free(ctx_);
        EVP_MAC_free(mac_);
        throw std::runtime_error("Ошибка инициализации HMAC.");
    }
}

template <size_t KeyLen>
void OpenSSLStreebog512HMAC<KeyLen>::update(const uint8_t *data, const size_t size) {
    if (!EVP_MAC_update(ctx_, data, size))
        throw std::runtime_error("Ошибка обновления HMAC.");
}

template <size_t KeyLen>
std::vector<uint8_t> OpenSSLStreebog512HMAC<KeyLen>::digest() {
    std::vector<uint8_t> out(64);
    if (!EVP_MAC_final(ctx_, out.data(), NULL, 64))
        throw std::runtime_error("Ошибка получения финального значения HMAC.");
    return out;
}

template <size_t KeyLen>
void OpenSSLStreebog512HMAC<KeyLen>::digest(uint8_t *digest_buffer) {
    if (!EVP_MAC_final(ctx_, digest_buffer, NULL, 64))
        throw std::runtime_error("Ошибка получения финального значения HMAC.");
}

#endif