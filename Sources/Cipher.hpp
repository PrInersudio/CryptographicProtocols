#ifndef CIPHER_HPP
#define CIPHER_HPP

#include "SecureBuffer.hpp"

template <size_t BlockSize>
class Cipher {
public:
    virtual SecureBuffer<BlockSize> &encrypt(SecureBuffer<BlockSize> &) const = 0;
    virtual SecureBuffer<BlockSize> &decrypt(SecureBuffer<BlockSize> &) const = 0;
    virtual ~Cipher() {}
};

#endif