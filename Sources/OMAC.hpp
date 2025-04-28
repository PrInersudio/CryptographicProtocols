#ifndef OMAC_HPP
#define OMAC_HPP

#include <vector>
#include "Cipher.hpp"

template <size_t BlockSize>
class OMAC {
private:
    SecureBuffer<BlockSize> buf_;
    size_t buffered_len_;
    SecureBuffer<BlockSize> accumulator_;
    SecureBuffer<BlockSize> key1_;
    SecureBuffer<BlockSize> key2_;
    const Cipher<BlockSize> &ctx_;

    void pad();
public:
    OMAC(const Cipher<BlockSize> &ctx);
    void update(const std::vector<uint8_t> &data);
    std::vector<uint8_t> digest(const size_t size = BlockSize);
#ifdef UNIT_TESTS
    const SecureBuffer<BlockSize> &getAccumulator() const;
    const SecureBuffer<BlockSize> &getKey1() const;
    const SecureBuffer<BlockSize> &getKey2() const;
#endif
};

template <size_t BlockSize>
static void transformAdditionalKey(SecureBuffer<BlockSize> &key) {
    static const auto B = []() -> SecureBuffer<BlockSize>{
        if constexpr (BlockSize == 8) {
            return SecureBuffer<8>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b};
        } else {
            return SecureBuffer<16>{
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
            };
        }
    }();
    if (key[0] & 0b10000000) (key <<= 1) += B;
    else (key <<= 1);
}

template <size_t BlockSize>
void OMAC<BlockSize>::pad() {
    buf_[buffered_len_] = 0x80;    
    for (size_t i = buffered_len_ + 1; i < BlockSize; ++i)
        buf_[i] = 0;
}

template <size_t BlockSize>
OMAC<BlockSize>::OMAC(const Cipher<BlockSize> &ctx) : buffered_len_(0),  ctx_(ctx) {
    static_assert(
        BlockSize == 8 || BlockSize == 16,
        "OMAC. Использование размеров блока, отличных от 64 и 128 бит пока не предусмотренно."
    );
    key1_.zero(); ctx_.encrypt(key1_); transformAdditionalKey(key1_);
    key2_ = key1_; transformAdditionalKey(key2_);
    accumulator_.zero();
}

template <size_t BlockSize>
void OMAC<BlockSize>::update(const std::vector<uint8_t> &data) {
    if (data.empty()) return;
    size_t current_index = 0;
    do {
        if (buffered_len_ == BlockSize) {
            ctx_.encrypt(accumulator_ += buf_);
            buffered_len_ = 0;
        }
        size_t to_copy = std::min(BlockSize - buffered_len_, data.size() - current_index);
        buf_.insert(data.begin() + current_index, data.begin() + current_index + to_copy, buffered_len_);
        buffered_len_ += to_copy;
        current_index += to_copy;
    } while (data.size() - current_index > 0);
}

template <size_t BlockSize>
std::vector<uint8_t> OMAC<BlockSize>::digest(const size_t size) {
    if (size > BlockSize)
        throw std::out_of_range("Запрошен размер MAC больше длины блока выбранного шифра.");
    const SecureBuffer<BlockSize> *final_key;
    if (buffered_len_ == BlockSize)
        final_key = &key1_;
    else {
        pad();
        final_key = &key2_;
    }
    ctx_.encrypt((accumulator_ += buf_) += *final_key);
    std::vector<uint8_t> result(accumulator_.begin(), accumulator_.begin() + size);
    return result;
}

#ifdef UNIT_TESTS
template <size_t BlockSize>
const SecureBuffer<BlockSize> &OMAC<BlockSize>::getAccumulator() const {
    return accumulator_;
}
template <size_t BlockSize>
const SecureBuffer<BlockSize> &OMAC<BlockSize>::getKey1() const {
    return key1_;
}
template <size_t BlockSize>
const SecureBuffer<BlockSize> &OMAC<BlockSize>::getKey2() const {
    return key2_;
}
#endif

#endif