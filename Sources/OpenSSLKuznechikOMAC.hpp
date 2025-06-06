#ifndef OPENSSLKUZNECHIKOMAC_HPP
#define OPENSSLKUZNECHIKOMAC_HPP

#include <stdexcept>
#include <openssl/evp.h>
#include "SecureBuffer.hpp"
#include "Hash.hpp"

class OpenSSLKuznechikOMAC : public MAC<16, 16, 32> {
private:
    EVP_MAC_CTX* ctx_;
    EVP_MAC* mac_;
    SecureBuffer<32> key_;

    inline void free() noexcept { 
        if (ctx_) EVP_MAC_CTX_free(ctx_);
        if (mac_) EVP_MAC_free(mac_);
        ctx_ = nullptr;
        mac_ = nullptr;
    }
public:
    OpenSSLKuznechikOMAC() : ctx_(nullptr), mac_(nullptr) {}
    void initKeySchedule(const SecureBuffer<32> &key) override;
    inline OpenSSLKuznechikOMAC(const SecureBuffer<32> &key) : OpenSSLKuznechikOMAC()
        { initKeySchedule(key); }
    inline ~OpenSSLKuznechikOMAC() { free(); }
    void update(const uint8_t *data, const size_t size) override;
    inline void update(const std::vector<uint8_t> &data) override
        { update(data.data(), data.size()); }
    std::vector<uint8_t> digest(const size_t size);
    inline std::vector<uint8_t> digest() override
        { return digest(16); }
    void digest(uint8_t *digest_buffer) override;
    inline void clear() override { free(); initKeySchedule(key_); }

    static constexpr size_t BlockSize = 16;
    static constexpr size_t DigestSize = 16;
    static constexpr size_t KeySize = 32;
};
#endif