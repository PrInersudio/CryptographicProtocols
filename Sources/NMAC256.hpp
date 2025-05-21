// Согласно определению в Р 1323565.1.022—2018
#ifndef NMAC256_HPP
#define NMAC256_HPP

#include "Hash.hpp"
#include "Streebog.hpp"

template <size_t KeySize>
class NMAC256 : public MAC<64, 32, KeySize> {
private:
    Streebog512 inner_hasher_;
    SecureBuffer<64> padded_key_;
public:
    NMAC256() = default;
    void initKeySchedule(const SecureBuffer<KeySize> &key) noexcept override;
    inline NMAC256(const SecureBuffer<KeySize> &key) noexcept
        { initKeySchedule(key); }
    inline void update(const uint8_t *data, const size_t size) noexcept override
        { inner_hasher_.update(data, size); }
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { inner_hasher_.update(data); }
    std::vector<uint8_t> digest() noexcept override;
    void digest(uint8_t *digest_buffer) noexcept override;
    void clear() noexcept override;
};

template <size_t KeySize>
void NMAC256<KeySize>::initKeySchedule(const SecureBuffer<KeySize> &key) noexcept {
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
std::vector<uint8_t> NMAC256<KeySize>::digest() noexcept {
    SecureBuffer<64> inner_digest;
    inner_hasher_.digest(inner_digest.raw());
    Streebog256 outer_hasher;
    outer_hasher.update(padded_key_.raw(), 64);
    outer_hasher.update(inner_digest.raw(), 64);
    return outer_hasher.digest();
}

template <size_t KeySize>
void NMAC256<KeySize>::digest(uint8_t *digest_buffer) noexcept {
    SecureBuffer<64> inner_digest;
    inner_hasher_.digest(inner_digest.raw());
    Streebog256 outer_hasher;
    outer_hasher.update(padded_key_.raw(), 64);
    outer_hasher.update(inner_digest.raw(), 64);
    outer_hasher.digest(digest_buffer);
}

template <size_t KeySize>
void NMAC256<KeySize>::clear() noexcept{
    inner_hasher_.clear();
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x5c ^ 0x36);
    inner_hasher_.update(padded_key_.raw(), 64);
    for (size_t i = 0; i < 64; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

#endif
