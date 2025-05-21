#ifndef CIPHER_HPP
#define CIPHER_HPP

#include "SecureBuffer.hpp"

template <size_t BlockSize, size_t KeySize>
class Cipher {
public:
    virtual void initKeySchedule(const SecureBuffer<KeySize> &key) = 0;
    virtual SecureBuffer<BlockSize> &encrypt(SecureBuffer<BlockSize> &) const = 0;
    virtual SecureBuffer<BlockSize> &decrypt(SecureBuffer<BlockSize> &) const = 0;
    virtual ~Cipher() = default;
};

template <typename T>
concept IsCipher = requires(const SecureBuffer<T::KeySize> &key) {
    { T() };
    { T(key) };
    { T::BlockSize } -> std::same_as<const size_t &>;
    { T::KeySize } -> std::same_as<const size_t &>;
    requires std::is_base_of_v<Cipher<T::BlockSize, T::KeySize>, T>;
    
};

#endif