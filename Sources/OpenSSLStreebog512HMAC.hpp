#ifndef OPENSSLSTREEBOG512HMAC
#define OPENSSLSTREEBOG512HMAC

#include <openssl/evp.h>
#include <stdexcept>
#include "Hash.hpp"
#include "SecureBuffer.hpp"

template <size_t KeySize>
class OpenSSLStreebog512HMAC : public MAC<64, 64, KeySize> {
private:
    EVP_MAC_CTX *ctx_;
    EVP_MAC* mac_;
    SecureBuffer<KeySize> key_;

    inline void free() noexcept { 
        if (ctx_) EVP_MAC_CTX_free(ctx_);
        if (mac_) EVP_MAC_free(mac_);
        ctx_ = nullptr;
        mac_ = nullptr;
    }
public:
    OpenSSLStreebog512HMAC() : ctx_(nullptr), mac_(nullptr) {}
    void initKeySchedule(const SecureBuffer<KeySize> &key) override;
    inline OpenSSLStreebog512HMAC(const SecureBuffer<KeySize> &key)
        { initKeySchedule(key); }
    void update(const uint8_t *data, const size_t size);
    inline void update(const std::vector<uint8_t> &data)
        { update(data.data(), data.size()); }
    std::vector<uint8_t> digest();
    void digest(uint8_t *digest_buffer);
    inline void clear() override { free(); initKeySchedule(key_); }
    inline ~OpenSSLStreebog512HMAC() noexcept { free(); }
};

template <size_t KeySize>
void OpenSSLStreebog512HMAC<KeySize>::initKeySchedule(const SecureBuffer<KeySize> &key) {
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
    if (!EVP_MAC_init(ctx_, key_.raw(), KeySize, params)) {
        EVP_MAC_CTX_free(ctx_);
        EVP_MAC_free(mac_);
        throw std::runtime_error("Ошибка инициализации HMAC.");
    }
}

template <size_t KeySize>
void OpenSSLStreebog512HMAC<KeySize>::update(const uint8_t *data, const size_t size) {
    if (!EVP_MAC_update(ctx_, data, size))
        throw std::runtime_error("Ошибка обновления HMAC.");
}

template <size_t KeySize>
std::vector<uint8_t> OpenSSLStreebog512HMAC<KeySize>::digest() {
    std::vector<uint8_t> out(64);
    if (!EVP_MAC_final(ctx_, out.data(), NULL, 64))
        throw std::runtime_error("Ошибка получения финального значения HMAC.");
    return out;
}

template <size_t KeySize>
void OpenSSLStreebog512HMAC<KeySize>::digest(uint8_t *digest_buffer) {
    if (!EVP_MAC_final(ctx_, digest_buffer, NULL, 64))
        throw std::runtime_error("Ошибка получения финального значения HMAC.");
}

#endif