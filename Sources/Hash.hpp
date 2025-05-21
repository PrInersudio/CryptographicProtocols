#ifndef HASH_HPP
#define HASH_HPP

#include <vector>
#include <cinttypes>
#include "SecureBuffer.hpp"

template <size_t BlockSize, size_t DigestSize>
class Hash {
public:
    virtual void update(const std::vector<uint8_t> &data) = 0;
    virtual void update(const uint8_t *data, const size_t size) = 0;
    virtual std::vector<uint8_t> digest() = 0;
    virtual void digest(uint8_t *digest_buffer) = 0;
    virtual void clear() = 0;
    virtual ~Hash() = default;
};

template <typename T>
concept IsHash = requires {
    { T() };
    { T::BlockSize } -> std::same_as<const size_t &>;
    { T::DigestSize } -> std::same_as<const size_t &>;
    requires std::is_base_of_v<Hash<T::BlockSize, T::DigestSize>, T>;
};

template <size_t BlockSize, size_t DigestSize, size_t KeySize>
class MAC : public Hash<BlockSize, DigestSize> {
public:
    virtual void initKeySchedule(const SecureBuffer<KeySize> &key) = 0;
};

template <typename T>
concept IsMAC= requires(const SecureBuffer<T::KeySize> &key) {
    { T() };
    { T(key) };
    { T::BlockSize } -> std::same_as<const size_t &>;
    { T::DigestSize } -> std::same_as<const size_t &>;
    { T::KeySize } -> std::same_as<const size_t &>;
    requires std::is_base_of_v<MAC<T::BlockSize, T::DigestSize, T::KeySize>, T>;
};

#endif