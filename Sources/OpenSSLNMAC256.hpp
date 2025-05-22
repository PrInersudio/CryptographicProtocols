// Согласно определению в Р 1323565.1.022—2018
#ifndef OPENSSLNMAC256_HPP
#define OPENSSLNMAC256_HPP

#include "SecureBuffer.hpp"
#include "OpenSSLHash.hpp"

template <size_t KeyLen>
class OpenSSLNMAC256 : public MAC<64, 32, KeyLen> {
private:
    OpenSSLHash<64,64> inner_hasher_;
    OpenSSLHash<64,32> outer_hasher_;
    SecureBuffer<64> padded_key_;
public:
    OpenSSLNMAC256() : inner_hasher_(SN_id_GostR3411_2012_512), outer_hasher_(SN_id_GostR3411_2012_256) {}
    void initKeySchedule(const SecureBuffer<KeyLen> &key) override;
    OpenSSLNMAC256(const SecureBuffer<KeyLen> &key) : OpenSSLNMAC256()
        { initKeySchedule(key); }
    inline void update(const uint8_t *data, const size_t size) noexcept override
        { inner_hasher_.update(data, size); }
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { inner_hasher_.update(data); }
    std::vector<uint8_t> digest() noexcept override;
    void digest(uint8_t *digest_buffer) noexcept override;
    void clear() noexcept override;

    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 32;
    static constexpr size_t KeySize = KeyLen;
};

template <size_t KeyLen>
void OpenSSLNMAC256<KeyLen>::initKeySchedule(const SecureBuffer<KeyLen> &key) {
    padded_key_.zero();
    if constexpr (KeyLen > 64) {
        inner_hasher_.update(key.raw(), KeyLen);
        inner_hasher_.digest(padded_key_.raw());
        inner_hasher_.clear();
    } else
        std::copy(key.begin(), key.end(), padded_key_.begin());
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= 0x36;
    inner_hasher_.update(padded_key_.raw(), 64);
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

template <size_t KeyLen>
std::vector<uint8_t> OpenSSLNMAC256<KeyLen>::digest() noexcept {
    SecureBuffer<64> inner_digest;
    inner_hasher_.digest(inner_digest.raw());
    outer_hasher_.update(padded_key_.raw(), 64);
    outer_hasher_.update(inner_digest.raw(), 64);
    return outer_hasher_.digest();
}

template <size_t KeyLen>
void OpenSSLNMAC256<KeyLen>::digest(uint8_t *digest_buffer) noexcept {
    SecureBuffer<64> inner_digest;
    inner_hasher_.digest(inner_digest.raw());
    outer_hasher_.update(padded_key_.raw(), 64);
    outer_hasher_.update(inner_digest.raw(), 64);
    outer_hasher_.digest(digest_buffer);
}

template <size_t KeyLen>
void OpenSSLNMAC256<KeyLen>::clear() noexcept{
    inner_hasher_.clear();
    outer_hasher_.clear();
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x5c ^ 0x36);
    inner_hasher_.update(padded_key_.raw(), 64);
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

#endif
