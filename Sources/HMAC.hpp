#ifndef HMAC_HPP
#define HMAC_HPP

#include "Hash.hpp"
#include "SecureBuffer.hpp"

template <size_t BlockSize, size_t DigestSize, size_t KeySize>
class HMAC : public MAC<BlockSize, DigestSize> {
private:
    Hash<BlockSize, DigestSize> &hash_;
    SecureBuffer<BlockSize> padded_key_;
public:
    HMAC(Hash<BlockSize, DigestSize> &hash, const SecureBuffer<KeySize> &key) noexcept;
    inline void update(const uint8_t *data, const size_t size) noexcept override
        { hash_.update(data, size); }
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { hash_.update(data); }
    std::vector<uint8_t> digest() noexcept override;
    void digest(uint8_t *digest_buffer) noexcept override;
    void clear() noexcept override;
};

template <size_t BlockSize, size_t DigestSize, size_t KeySize>
HMAC<BlockSize, DigestSize, KeySize>::HMAC(Hash<BlockSize, DigestSize> &hash,
    const SecureBuffer<KeySize> &key) noexcept : hash_(hash)
{
    static_assert(DigestSize <= BlockSize,
        "Размер подписи базового хэша не может быть больше его размера блока.");
    padded_key_.zero();
    if constexpr (KeySize > BlockSize) {
        hash_.update(key.raw(), KeySize);
        hash_.digest(padded_key_.raw());
        hash_.clear();
    } else
        std::copy(key.begin(), key.end(), padded_key_.begin());
    for (size_t i = 0; i < BlockSize; ++i)
        padded_key_[i] ^= 0x36;
    hash_.update(padded_key_.raw(), BlockSize);
    for (size_t i = 0; i < BlockSize; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

template <size_t BlockSize, size_t DigestSize, size_t KeySize>
std::vector<uint8_t> HMAC<BlockSize, DigestSize, KeySize>::digest() noexcept {
    SecureBuffer<DigestSize> inner_digest;
    hash_.digest(inner_digest.raw());
    hash_.clear();
    hash_.update(padded_key_.raw(), BlockSize);
    hash_.update(inner_digest.raw(), DigestSize);
    return hash_.digest();
}

template <size_t BlockSize, size_t DigestSize, size_t KeySize>
void HMAC<BlockSize, DigestSize, KeySize>::digest(uint8_t *digest_buffer) noexcept {
    SecureBuffer<DigestSize> inner_digest;
    hash_.digest(inner_digest.raw());
    hash_.clear();
    hash_.update(padded_key_.raw(), BlockSize);
    hash_.update(inner_digest.raw(), DigestSize);
    hash_.digest(digest_buffer);
}


template <size_t BlockSize, size_t DigestSize, size_t KeySize>
void HMAC<BlockSize, DigestSize, KeySize>::clear() noexcept{
    hash_.clear();
    for (size_t i = 0; i < BlockSize; ++i)
        padded_key_[i] ^= (0x5c ^ 0x36);
    hash_.update(padded_key_.raw(), BlockSize);
    for (size_t i = 0; i < BlockSize; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

#endif