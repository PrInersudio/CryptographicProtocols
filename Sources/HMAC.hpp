#ifndef HMAC_HPP
#define HMAC_HPP

#include "Hash.hpp"
#include "SecureBuffer.hpp"

template <IsHash HashType, size_t KeySize>
class HMAC : public MAC<HashType::BlockSize, HashType::DigestSize> {
private:
    HashType hash_;
    SecureBuffer<HashType::BlockSize> padded_key_;
public:
    HMAC(const SecureBuffer<KeySize> &key) noexcept;
    inline void update(const uint8_t *data, const size_t size) noexcept override
        { hash_.update(data, size); }
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { hash_.update(data); }
    std::vector<uint8_t> digest() noexcept override;
    void digest(uint8_t *digest_buffer) noexcept override;
    void clear() noexcept override;
};

template <IsHash HashType, size_t KeySize>
HMAC<HashType, KeySize>::HMAC(const SecureBuffer<KeySize> &key) noexcept {
    static_assert(HashType::DigestSize <= HashType::BlockSize,
        "Размер подписи базового хэша не может быть больше его размера блока.");
    padded_key_.zero();
    if constexpr (KeySize > HashType::BlockSize) {
        hash_.update(key.raw(), KeySize);
        hash_.digest(padded_key_.raw());
        hash_.clear();
    } else
        std::copy(key.begin(), key.end(), padded_key_.begin());
    for (size_t i = 0; i < HashType::BlockSize; ++i)
        padded_key_[i] ^= 0x36;
    hash_.update(padded_key_.raw(), HashType::BlockSize);
    for (size_t i = 0; i < HashType::BlockSize; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

template <IsHash HashType, size_t KeySize>
std::vector<uint8_t> HMAC<HashType, KeySize>::digest() noexcept {
    SecureBuffer<HashType::DigestSize> inner_digest;
    hash_.digest(inner_digest.raw());
    hash_.clear();
    hash_.update(padded_key_.raw(), HashType::BlockSize);
    hash_.update(inner_digest.raw(), HashType::DigestSize);
    return hash_.digest();
}

template <IsHash HashType, size_t KeySize>
void HMAC<HashType, KeySize>::digest(uint8_t *digest_buffer) noexcept {
    SecureBuffer<HashType::DigestSize> inner_digest;
    hash_.digest(inner_digest.raw());
    hash_.clear();
    hash_.update(padded_key_.raw(), HashType::BlockSize);
    hash_.update(inner_digest.raw(), HashType::DigestSize);
    hash_.digest(digest_buffer);
}


template <IsHash HashType, size_t KeySize>
void HMAC<HashType, KeySize>::clear() noexcept{
    hash_.clear();
    for (size_t i = 0; i < HashType::BlockSize; ++i)
        padded_key_[i] ^= (0x5c ^ 0x36);
    hash_.update(padded_key_.raw(), HashType::BlockSize);
    for (size_t i = 0; i < HashType::BlockSize; ++i)
        padded_key_[i] ^= (0x36 ^ 0x5c);
}

#endif