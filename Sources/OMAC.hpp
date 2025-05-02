#ifndef OMAC_HPP
#define OMAC_HPP

#include <vector>
#include "Cipher.hpp"

template <size_t BlockSize>
class OMAC {
private:
    uint8_t buf_[BlockSize];
    size_t buffered_len_;
    SecureBuffer<BlockSize> accumulator_;
    SecureBuffer<BlockSize> key1_;
    SecureBuffer<BlockSize> key2_;
    const Cipher<BlockSize> &ctx_;

    void inline pad() noexcept {
        buf_[buffered_len_] = 0x80;    
        for (size_t i = buffered_len_ + 1; i < BlockSize; ++i)
            buf_[i] = 0;
    }
public:
    OMAC(const Cipher<BlockSize> &ctx) noexcept;
    void update(const std::vector<uint8_t> &data) noexcept;
    std::vector<uint8_t> digest(const size_t size = BlockSize);
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
void OMAC<BlockSize>::update(const std::vector<uint8_t> &data) noexcept {
    if (data.empty()) return;
    size_t current_index = 0;
    do {
        if (buffered_len_ == BlockSize) {
            ctx_.encrypt(accumulator_ += buf_);
            buffered_len_ = 0;
        }
        size_t to_copy = std::min(BlockSize - buffered_len_, data.size() - current_index);
        std::copy(
            data.begin() + static_cast<ptrdiff_t>(current_index),
            data.begin() + static_cast<ptrdiff_t>(current_index + to_copy),
            buf_ + buffered_len_
        );
        buffered_len_ += to_copy;
        current_index += to_copy;
    } while (data.size() - current_index > 0);
}

template <size_t BlockSize>
std::vector<uint8_t> OMAC<BlockSize>::digest(const size_t size) {
    if (size > BlockSize)
        throw std::invalid_argument("Запрошен размер MAC больше длины блока выбранного шифра.");
    const SecureBuffer<BlockSize> *final_key;
    if (buffered_len_ == BlockSize)
        final_key = &key1_;
    else {
        pad();
        final_key = &key2_;
    }
    ctx_.encrypt((accumulator_ += buf_) += *final_key);
    return std::vector<uint8_t>(accumulator_.begin(), accumulator_.begin() + size);
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