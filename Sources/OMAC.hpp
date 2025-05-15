#ifndef OMAC_HPP
#define OMAC_HPP

#include <vector>
#include "Cipher.hpp"
#include "Hash.hpp"

template <size_t BlockSize>
class OMAC : public MAC<BlockSize, BlockSize> {
private:
    SecureBuffer<BlockSize> buf_;
    size_t buffered_len_;
    SecureBuffer<BlockSize> accumulator_;
    SecureBuffer<BlockSize> key1_;
    SecureBuffer<BlockSize> key2_;
    const Cipher<BlockSize> &ctx_;

    void finalize() noexcept;

    void inline pad() noexcept {
        buf_[buffered_len_] = 0x80;    
        for (size_t i = buffered_len_ + 1; i < BlockSize; ++i)
            buf_[i] = 0;
    }
public:
    OMAC(const Cipher<BlockSize> &ctx) noexcept;
    void update(const uint8_t *data, const size_t size) noexcept override;
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { update(data.data(), data.size()); }
    std::vector<uint8_t> digest(const size_t size);
    inline std::vector<uint8_t> digest() override { return digest(BlockSize); }
    void digest(uint8_t *digest_buffer) noexcept override;

    inline void clear() noexcept override
        { buffered_len_ = 0; accumulator_.zero(); }

#ifdef UNIT_TESTS
    const SecureBuffer<BlockSize> &getAccumulator() const noexcept;
    const SecureBuffer<BlockSize> &getKey1() const noexcept;
    const SecureBuffer<BlockSize> &getKey2() const noexcept;
#endif
};

template <size_t BlockSize>
static inline void transformAdditionalKey(SecureBuffer<BlockSize> &key) noexcept {
    static constexpr uint8_t B = BlockSize == 8 ? 0x1b : 0x87;
    if (key[0] & 0b10000000) {
        key <<= 1;
        key[BlockSize - 1] ^= B;
    } else key <<= 1;
}

template <size_t BlockSize>
OMAC<BlockSize>::OMAC(const Cipher<BlockSize> &ctx) noexcept : buffered_len_(0),  ctx_(ctx) {
    static_assert(
        BlockSize == 8 || BlockSize == 16,
        "OMAC. Использование размеров блока, отличных от 64 и 128 бит пока не предусмотренно."
    );
    key1_.zero(); ctx_.encrypt(key1_); transformAdditionalKey(key1_);
    key2_ = key1_; transformAdditionalKey(key2_);
    accumulator_.zero();
}

template <size_t BlockSize>
void OMAC<BlockSize>::update(const uint8_t *data, const size_t size) noexcept {
    size_t current_index = 0;
    while (size - current_index > 0) {
        if (buffered_len_ == BlockSize) {
            ctx_.encrypt(accumulator_ += buf_);
            buffered_len_ = 0;
        }
        size_t to_copy = std::min(BlockSize - buffered_len_, size - current_index);
        std::copy(
            data + static_cast<ptrdiff_t>(current_index),
            data + static_cast<ptrdiff_t>(current_index + to_copy),
            buf_.begin() + buffered_len_
        );
        buffered_len_ += to_copy;
        current_index += to_copy;
    }
}

template <size_t BlockSize>
void OMAC<BlockSize>::finalize() noexcept {
    const SecureBuffer<BlockSize> *final_key;
    if (buffered_len_ == BlockSize)
        final_key = &key1_;
    else {
        pad();
        final_key = &key2_;
    }
    ctx_.encrypt((accumulator_ += buf_) += *final_key);
}

template <size_t BlockSize>
std::vector<uint8_t> OMAC<BlockSize>::digest(const size_t size) {
    if (size > BlockSize)
        throw std::invalid_argument("Запрошен размер MAC больше длины блока выбранного шифра.");
    finalize();
    return std::vector<uint8_t>(accumulator_.begin(), accumulator_.begin() + size);
}

template <size_t BlockSize>
void OMAC<BlockSize>::digest(uint8_t *digest_buffer) noexcept {
    finalize();
    std::copy(accumulator_.begin(), accumulator_.end(), digest_buffer);
}

#ifdef UNIT_TESTS
template <size_t BlockSize>
const SecureBuffer<BlockSize> &OMAC<BlockSize>::getAccumulator() const noexcept {
    return accumulator_;
}
template <size_t BlockSize>
const SecureBuffer<BlockSize> &OMAC<BlockSize>::getKey1() const noexcept {
    return key1_;
}
template <size_t BlockSize>
const SecureBuffer<BlockSize> &OMAC<BlockSize>::getKey2() const noexcept {
    return key2_;
}
#endif

#endif