// Согласно определению в Р 1323565.1.022—2018
#ifndef OPENSSLNMAC256_HPP
#define OPENSSLNMAC256_HPP

#include "SecureBuffer.hpp"
#include "OpenSSLHash.hpp"

template <size_t KeySize>
class OpenSSLNMAC256 : public MAC<64, 32> {
private:
    OpenSSLHash<64,64> inner_hasher_;
    OpenSSLHash<64,32> outer_hasher_;
    SecureBuffer<64> padded_key_;
public:
    OpenSSLNMAC256(const SecureBuffer<KeySize> &key);
    inline void update(const uint8_t *data, const size_t size) noexcept override
        { inner_hasher_.update(data, size); }
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { inner_hasher_.update(data); }
    std::vector<uint8_t> digest() noexcept override;
    void digest(uint8_t *digest_buffer) noexcept override;
    void clear() noexcept override;
};

template <size_t KeySize>
OpenSSLNMAC256<KeySize>::OpenSSLNMAC256(const SecureBuffer<KeySize> &key)
: inner_hasher_(SN_id_GostR3411_2012_512), outer_hasher_(SN_id_GostR3411_2012_256)
{
    padded_key_.zero();
    if constexpr (KeySize > 64) {
        inner_hasher_.update(key.raw(), KeySize);
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

template <size_t KeySize>
std::vector<uint8_t> OpenSSLNMAC256<KeySize>::digest() noexcept {
    SecureBuffer<64> inner_digest;
    inner_hasher_.digest(inner_digest.raw());
    outer_hasher_.update(padded_key_.raw(), 64);
    outer_hasher_.update(inner_digest.raw(), 64);
    return outer_hasher_.digest();
}

template <size_t KeySize>
void OpenSSLNMAC256<KeySize>::digest(uint8_t *digest_buffer) noexcept {
    SecureBuffer<64> inner_digest;
    inner_hasher_.digest(inner_digest.raw());
    outer_hasher_.update(padded_key_.raw(), 64);
    outer_hasher_.update(inner_digest.raw(), 64);
    outer_hasher_.digest(digest_buffer);
}

template <size_t KeySize>
void OpenSSLNMAC256<KeySize>::clear() noexcept{
    inner_hasher_.clear();
    outer_hasher_.clear();
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x5c ^ 0x36);
    inner_hasher_.update(padded_key_.raw(), 64);
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

#endif
