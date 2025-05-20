#ifndef CTR_DRBG_HPP
#define CTR_DRBG_HPP

#include <fstream>
#include "Cipher.hpp"
#include "Hash.hpp"
#include "EntropySource.hpp"

#ifdef DEBUG_PRINT
#include <iostream>
#include <iomanip>

template <size_t N>
void Print(const SecureBuffer<N>& data, const std::string &pref) {
    std::cout << pref << ": " << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t b : data)
        std::cout << std::setw(2) << static_cast<int>(b);
    std::cout << std::endl;
}
#endif

template <
    IsCipher CipherType,
    bool AutoReseed = false,
    IsEntropySource<CipherType::BlockSize + CipherType::KeySize> EntropySourceType =
        Urandom<CipherType::BlockSize + CipherType::KeySize>
>
class CTR_DRBG {
private:
    static constexpr size_t SeedLen = CipherType::BlockSize + CipherType::KeySize;
    static constexpr size_t ReseedInterval =
        CipherType::BlockSize < 16 ? (static_cast<size_t>(1) << 32) : (static_cast<size_t>(1) << 48);

    const EntropySourceType entropy_source_;
    SecureBuffer<CipherType::BlockSize> state_;
    size_t reseed_counter_;
    CipherType cipher_;
    
#ifndef CTR_DRBG_BIG_ENDIAN_STATE
    inline void incState() noexcept {
        uint16_t carry = 1;
        for (size_t i = 0; i < CipherType::BlockSize && carry; ++i) {
            carry = static_cast<uint16_t>(state_[i]) + carry;
            state_[i] = static_cast<uint8_t>(carry);
            carry >>= 8;
        }
    }
    void update(const SecureBuffer<SeedLen> &provided_data) noexcept;
#else
    inline void incState() noexcept {
        uint16_t carry = 1;
        for (size_t i = 0; i < CipherType::BlockSize && carry; ++i) {
            carry = static_cast<uint16_t>(state_[CipherType::BlockSize - 1 - i]) + carry;
            state_[CipherType::BlockSize - 1 - i] = static_cast<uint8_t>(carry);
            carry >>= 8;
        }
    }
    void update(const SecureBuffer<SeedLen> &provided_data) noexcept;
#endif
public:
    inline CTR_DRBG(
        const uint8_t *personalization_string  = nullptr,
        const size_t personalization_string_len = 0
    ) {
        SecureBuffer<CipherType::KeySize> key; key.zero();
        cipher_.initKeySchedule(key);
        state_.zero();
        reseed(personalization_string, personalization_string_len);
    }
    inline void reseed(
        const uint8_t *additional_input = nullptr,
        const size_t additional_input_len = 0
    ) {
        SecureBuffer<SeedLen> seed; seed.zero();
        if (additional_input) {
            size_t to_copy = std::min(SeedLen, additional_input_len);
            memcpy(seed.raw(), additional_input, to_copy);
        }
        seed += entropy_source_();
        update(seed);
        reseed_counter_ = 1;
    }
    int operator()(
        uint8_t *buffer, size_t size,
        const uint8_t *additional_input = nullptr,
        const size_t additional_input_len = 0
    ) noexcept;
};

template <IsCipher CipherType, bool AutoReseed, IsEntropySource<CipherType::BlockSize + CipherType::KeySize> EntropySourceType>
void CTR_DRBG<CipherType, AutoReseed, EntropySourceType>::update(const SecureBuffer<SeedLen> &provided_data) noexcept {
    static constexpr size_t num_of_blocks = SeedLen / CipherType::BlockSize;
    static constexpr size_t remainder = SeedLen % CipherType::BlockSize;
    
    SecureBuffer<SeedLen> temp;
    SecureBuffer<CipherType::BlockSize> block;
    for (size_t i = 0; i < num_of_blocks; ++i) {
        incState();
        block = state_;
        cipher_.encrypt(block);
        std::copy(block.begin(), block.end(), temp.begin() + i * CipherType::BlockSize);
    }
    if constexpr (remainder > 0) {
        incState();
        block = state_;
        cipher_.encrypt(block);
        std::copy(block.begin(), block.begin() + remainder,
            temp.begin() + (SeedLen - remainder));
    }
    temp += provided_data;
    SecureBuffer<CipherType::KeySize> key;
    std::copy(temp.begin(), temp.begin() + CipherType::KeySize, key.begin());
    std::copy(temp.begin() + CipherType::KeySize, temp.end(), state_.begin());
    cipher_.initKeySchedule(key);

    #ifdef DEBUG_PRINT
        Print(provided_data, "Provided Data");
        Print(key, "Key");
        Print(state_, "State");
    #endif
}

template <IsCipher CipherType, bool AutoReseed, IsEntropySource<CipherType::BlockSize + CipherType::KeySize> EntropySourceType>
int CTR_DRBG<CipherType, AutoReseed, EntropySourceType>::operator()(
    uint8_t *buffer, size_t size,
    const uint8_t *additional_input,
    const size_t additional_input_len
) noexcept {
    if (reseed_counter_ > ReseedInterval)
        { if constexpr (AutoReseed) reseed(); else return -1; }
    SecureBuffer<SeedLen> seed; seed.zero();
    if (additional_input) {
        size_t to_copy = std::min(SeedLen, additional_input_len);
        memcpy(seed.raw(), additional_input, to_copy);
        update(seed);
    }
    size_t num_of_blocks = size / CipherType::BlockSize;
    size_t remainder = size % CipherType::BlockSize;
    SecureBuffer<CipherType::BlockSize> block;
    for (size_t i = 0; i < num_of_blocks; ++i) {
        incState();
        block = state_;
        cipher_.encrypt(block);
        memcpy(buffer + i * CipherType::BlockSize, block.raw(), CipherType::BlockSize);
    }
    if (remainder > 0) {
        incState();
        block = state_;
        cipher_.encrypt(block);
        memcpy(buffer + (size - remainder), block.raw(), remainder);
    }
    update(seed);
    ++reseed_counter_;
    return 0;
}

#endif