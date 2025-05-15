#ifndef HASH_HPP
#define HASH_HPP

#include <vector>
#include <cinttypes>

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

template <size_t BlockSize, size_t DigestSize>
class MAC : public Hash<BlockSize, DigestSize> {};

#endif