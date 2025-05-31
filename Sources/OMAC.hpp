#ifndef OMAC_HPP
#define OMAC_HPP

#include <vector>
#include "Cipher.hpp"
#include "Hash.hpp"
#include "CRISPExceptions.hpp"

template <IsCipher CipherType>
class OMAC : public MAC<CipherType::BlockSize, CipherType::BlockSize, CipherType::KeySize> {
private:
    SecureBuffer<CipherType::BlockSize> buf_;
    size_t buffered_len_;
    SecureBuffer<CipherType::BlockSize> accumulator_;
    SecureBuffer<CipherType::BlockSize> digest_key_;
    CipherType ctx_;

    void finalize() noexcept;

    void inline pad() noexcept {
        buf_[buffered_len_] = 0x80;    
        for (size_t i = buffered_len_ + 1; i < CipherType::BlockSize; ++i)
            buf_[i] = 0;
    }
public:
    OMAC() : buffered_len_(0) {}
    void initKeySchedule(const SecureBuffer<CipherType::KeySize> &key) noexcept;
    inline OMAC(const SecureBuffer<CipherType::KeySize> &key) noexcept : OMAC()
        { initKeySchedule(key); }
    void update(const uint8_t *data, const size_t size) noexcept override;
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { update(data.data(), data.size()); }
    std::vector<uint8_t> digest(const size_t size);
    inline std::vector<uint8_t> digest() override { return digest(CipherType::BlockSize); }
    void digest(uint8_t *digest_buffer) noexcept override;
    inline void clear() noexcept override {
        buffered_len_ = 0; accumulator_.zero(); digest_key_.zero();
        ctx_.encrypt(digest_key_); transformAdditionalKey(digest_key_);
    }

    static constexpr size_t BlockSize = CipherType::BlockSize;
    static constexpr size_t DigestSize = CipherType::BlockSize;
    static constexpr size_t KeySize = CipherType::KeySize;

#ifdef UNIT_TESTS
    inline const SecureBuffer<CipherType::BlockSize> &getAccumulator() const noexcept
        { return accumulator_; }
    inline const SecureBuffer<CipherType::BlockSize> &getDigestKey() const noexcept
        { return digest_key_; }
    inline const CipherType &getCipherCTX() const noexcept
        { return ctx_; }
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

template <IsCipher CipherType>
void OMAC<CipherType>::initKeySchedule(const SecureBuffer<CipherType::KeySize> &key) noexcept {
    ctx_.initKeySchedule(key);
    static_assert(
        CipherType::BlockSize == 8 || CipherType::BlockSize == 16,
        "OMAC. Использование размеров блока, отличных от 64 и 128 бит пока не предусмотренно."
    );
    digest_key_.zero(); ctx_.encrypt(digest_key_); transformAdditionalKey(digest_key_);
    accumulator_.zero();
}

template <IsCipher CipherType>
void OMAC<CipherType>::update(const uint8_t *data, const size_t size) noexcept {
    size_t current_index = 0;
    while (size - current_index > 0) {
        if (buffered_len_ == CipherType::BlockSize) {
            ctx_.encrypt(accumulator_ += buf_);
            buffered_len_ = 0;
        }
        size_t to_copy = std::min(CipherType::BlockSize - buffered_len_, size - current_index);
        std::copy(
            data + static_cast<ptrdiff_t>(current_index),
            data + static_cast<ptrdiff_t>(current_index + to_copy),
            buf_.begin() + buffered_len_
        );
        buffered_len_ += to_copy;
        current_index += to_copy;
    }
}

template <IsCipher CipherType>
void OMAC<CipherType>::finalize() noexcept {
    if (buffered_len_ != CipherType::BlockSize) {
        pad();
        transformAdditionalKey(digest_key_);
    }
    ctx_.encrypt((accumulator_ += buf_) += digest_key_);
}

template <IsCipher CipherType>
std::vector<uint8_t> OMAC<CipherType>::digest(const size_t size) {
    if (size > CipherType::BlockSize)
        throw crispex::invalid_argument("Запрошен размер MAC больше длины блока выбранного шифра.");
    finalize();
    return std::vector<uint8_t>(accumulator_.begin(), accumulator_.begin() + size);
}

template <IsCipher CipherType>
void OMAC<CipherType>::digest(uint8_t *digest_buffer) noexcept {
    finalize();
    std::copy(accumulator_.begin(), accumulator_.end(), digest_buffer);
}

#endif