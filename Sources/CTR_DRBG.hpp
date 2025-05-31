#ifndef CTR_DRBG_HPP
#define CTR_DRBG_HPP

#include <fstream>

#ifndef DONT_USE_TBB
#include <tbb/parallel_for.h>
#include <tbb/blocked_range.h>
#endif

#define SECUREBUFFER_BIG_ENDIAN_COUNTER
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
    static constexpr size_t MaxBytesPerRequest =
        CipherType::BlockSize < 16 ? (static_cast<size_t>(1) << 10) : (static_cast<size_t>(1) << 16);
    static constexpr size_t ReseedInterval =
        CipherType::BlockSize < 16 ? (static_cast<size_t>(1) << 32) : (static_cast<size_t>(1) << 48);

    const EntropySourceType entropy_source_;
    SecureBuffer<CipherType::BlockSize> state_;
    size_t reseed_counter_;
    CipherType cipher_;

    void update(const SecureBuffer<SeedLen> &provided_data) noexcept;
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
        LOG(INFO) << "Инициализация/пересеевание ПДСЧ";
        SecureBuffer<SeedLen> seed; seed.zero();
        if (additional_input) {
            size_t to_copy = std::min(SeedLen, additional_input_len);
            memcpy(seed.raw(), additional_input, to_copy);
        }
        seed += entropy_source_();
        update(seed);
        reseed_counter_ = 1;
    }
    void operator()(
        uint8_t *buffer, size_t size,
        const uint8_t *additional_input = nullptr,
        const size_t additional_input_len = 0
    );
    inline uint64_t uint64(
        const uint8_t *additional_input = nullptr,
        const size_t additional_input_len = 0
    ) {
        uint64_t result;
        (*this)(reinterpret_cast<uint8_t *>(&result), 8, additional_input, additional_input_len);
        return result;
    }
};

template <IsCipher CipherType, bool AutoReseed, IsEntropySource<CipherType::BlockSize + CipherType::KeySize> EntropySourceType>
void CTR_DRBG<CipherType, AutoReseed, EntropySourceType>::update(const SecureBuffer<SeedLen> &provided_data) noexcept {
    static constexpr size_t num_of_blocks = SeedLen / CipherType::BlockSize;
    static constexpr size_t remainder = SeedLen % CipherType::BlockSize;
    
    SecureBuffer<SeedLen> temp;
    SecureBuffer<CipherType::BlockSize> block;
    for (size_t i = 0; i < num_of_blocks; ++i) {
        state_.add(1);
        block = state_;
        cipher_.encrypt(block);
        std::copy(block.begin(), block.end(), temp.begin() + i * CipherType::BlockSize);
    }
    if constexpr (remainder > 0) {
        state_.add(1);
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
void CTR_DRBG<CipherType, AutoReseed, EntropySourceType>::operator()(
    uint8_t *buffer, const size_t size,
    const uint8_t *additional_input,
    const size_t additional_input_len
) {
    if (size > MaxBytesPerRequest)
        throw crispex::rbg_query_limit("Запрошенный размер привышает максимум.");
    if (reseed_counter_ > ReseedInterval)
        { if constexpr (AutoReseed) reseed(); else throw crispex::rbg_reseed_await("Необходимо пересеевание для генерации случайных байт."); }
    LOG(INFO) << "Начат запрос к ПДСЧ " << reseed_counter_
              << " из " << ReseedInterval << " Запрошено " << size << " байт";
    SecureBuffer<SeedLen> seed; seed.zero();
    if (additional_input) {
        size_t to_copy = std::min(SeedLen, additional_input_len);
        memcpy(seed.raw(), additional_input, to_copy);
        update(seed);
    }
    size_t num_of_blocks = size / CipherType::BlockSize;
    size_t remainder = size % CipherType::BlockSize;
    #ifndef DONT_USE_TBB
    tbb::parallel_for(tbb::blocked_range<size_t>(0, num_of_blocks, 128),
    [&](const tbb::blocked_range<size_t>& r) {
        SecureBuffer<CipherType::BlockSize> block;
        for (size_t i = r.begin(); i != r.end(); ++i) {
            block = state_;
            block.add(i + 1);
            cipher_.encrypt(block);
            memcpy(buffer + i * CipherType::BlockSize, block.raw(), CipherType::BlockSize);
        }
    });
    state_.add(num_of_blocks);
    #else
    SecureBuffer<CipherType::BlockSize> block;
    for (size_t i = 0; i < num_of_blocks; ++i) {
        state_.add(1);
        block = state_;
        cipher_.encrypt(block);
        memcpy(buffer + i * CipherType::BlockSize, block.raw(), CipherType::BlockSize);
    }
    #endif
    if (remainder > 0) {
        state_.add(1);
        SecureBuffer<CipherType::BlockSize> block(state_);
        cipher_.encrypt(block);
        memcpy(buffer + (size - remainder), block.raw(), remainder);
    }
    update(seed);
    LOG(INFO) << "Закончен запрос к ПДСЧ " << reseed_counter_
              << " из " << ReseedInterval << " Выработано " << size << " байт";
    ++reseed_counter_;
}

#endif