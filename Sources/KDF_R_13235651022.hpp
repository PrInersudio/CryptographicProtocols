#ifndef KDF_R_13235651022_HPP
#define KDF_R_13235651022_HPP

#include <endian.h>
#include <memory>
#include "HMAC.hpp"
#include "NMAC256.hpp"
#include "Kuznechik.hpp"
#include "OMAC.hpp"

enum class FirstStageVariants { NMAC = 0, HMAC = 1, Simple = 2 };
enum class SecondStageVariants { NMAC = 0, HMAC256 = 1, HMAC512 = 2, CMAC = 3 };

template <SecondStageVariants V>
struct SecondStageMACParams;

template <>
struct SecondStageMACParams<SecondStageVariants::NMAC> {
    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 32;
};

template <>
struct SecondStageMACParams<SecondStageVariants::HMAC256> {
    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 32;
};

template <>
struct SecondStageMACParams<SecondStageVariants::HMAC512> {
    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 64;
};

template <>
struct SecondStageMACParams<SecondStageVariants::CMAC> {
    static constexpr size_t BlockSize = 16;
    static constexpr size_t DigestSize = 16;
};

template <
    FirstStageVariants FirstStageVariant,
    SecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
class KDF_R_13235651022 {
private:
    static constexpr size_t SecondStageMACBlockSize = SecondStageMACParams<SecondStageVariant>::BlockSize;
    static constexpr size_t SecondStageMACDigestSize = SecondStageMACParams<SecondStageVariant>::DigestSize;
    std::unique_ptr<MAC<SecondStageMACBlockSize, SecondStageMACDigestSize, 32>> second_stage_macer_;

    static void firstStage(
        SecureBuffer<32> &inner_key,
        const SecureBuffer<MasterKeySize> &master_key,
        const SecureBuffer<SaltSize> &salt
    ) noexcept;
    void initSecondStageMacer(SecureBuffer<32> &inner_key) noexcept;
public:
    KDF_R_13235651022() = default;
    inline void init(
        const SecureBuffer<MasterKeySize> &master_key,
        const SecureBuffer<SaltSize> &salt
    ) noexcept {
        SecureBuffer<32> inner_key;
        firstStage(inner_key, master_key, salt);
        initSecondStageMacer(inner_key);
    }
    KDF_R_13235651022(
        const SecureBuffer<MasterKeySize> &master_key,
        const SecureBuffer<SaltSize> &salt
    ) noexcept;
    void fetch(
        uint8_t *key, const uint64_t size,
        const uint8_t (&IV)[SecondStageMACDigestSize],
        const uint8_t (&application_info)[32],
        const uint8_t (&user_info)[16],
        const uint8_t (&additional_info)[16]
    ) noexcept;
};

template <
    FirstStageVariants FirstStageVariant,
    SecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
void KDF_R_13235651022<
FirstStageVariant, SecondStageVariant,
MasterKeySize, SaltSize
>::firstStage(
    SecureBuffer<32> &inner_key,
    const SecureBuffer<MasterKeySize> &master_key,
    const SecureBuffer<SaltSize> &salt
) noexcept {
    if constexpr (FirstStageVariant == FirstStageVariants::NMAC) {
        NMAC256<SaltSize> macer(salt);
        macer.update(master_key.raw(), MasterKeySize);
        macer.digest(inner_key.raw());
    }
    else if constexpr (FirstStageVariant == FirstStageVariants::HMAC) {
        HMAC<Streebog512, SaltSize> macer(salt);
        macer.update(master_key.raw(), MasterKeySize);
        SecureBuffer<64> big_inner_key;
        macer.digest(big_inner_key.raw());
        std::copy(big_inner_key.begin(), big_inner_key.begin() + 32, inner_key.begin());
    }
    else {
        static_assert(
            SaltSize == 32 && MasterKeySize == 32,
            "При использовании упрощённой конструкции ключ и соль должны быть строго длины 256 бит."
        );
        inner_key = master_key;
        inner_key += salt;
    }
}

template <
    FirstStageVariants FirstStageVariant,
    SecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
void KDF_R_13235651022<
    FirstStageVariant, SecondStageVariant,
    MasterKeySize, SaltSize
>::initSecondStageMacer(SecureBuffer<32> &inner_key) noexcept {
    if constexpr (SecondStageVariant == SecondStageVariants::NMAC)
        second_stage_macer_ = std::make_unique<NMAC256<32>>(inner_key);
    else if constexpr (SecondStageVariant == SecondStageVariants::HMAC256)
        second_stage_macer_ = std::make_unique<HMAC<Streebog256, 32>>(inner_key);
    else if constexpr (SecondStageVariant == SecondStageVariants::HMAC512)
        second_stage_macer_ = std::make_unique<HMAC<Streebog512, 32>>(inner_key);
    else
        second_stage_macer_ = std::make_unique<OMAC<Kuznechik>>(inner_key);
}

template <
    FirstStageVariants FirstStageVariant,
    SecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
KDF_R_13235651022<
    FirstStageVariant, SecondStageVariant,
    MasterKeySize, SaltSize
>::KDF_R_13235651022(
    const SecureBuffer<MasterKeySize> &master_key,
    const SecureBuffer<SaltSize> &salt
) noexcept {
    init(master_key, salt);
}

template <size_t SecondStageMACDigestSize>
inline static SecureBuffer<SecondStageMACDigestSize + 81> getFormat(
    const uint8_t (&IV)[SecondStageMACDigestSize],
    const uint8_t (&application_info)[32],
    const uint8_t (&user_info)[16],
    const uint8_t (&additional_info)[16],
    uint64_t size
) {
    SecureBuffer<SecondStageMACDigestSize + 81> format;
    format[0] = 0xFC;
    uint64_t counter = htole64(1);
    memcpy(format.raw() + 1, &counter, 8);
    memcpy(format.raw() + 9, IV, SecondStageMACDigestSize);
    size = htole64(size * 8);
    memcpy(format.raw() + SecondStageMACDigestSize + 9, &size, 8);
    memcpy(format.raw() + SecondStageMACDigestSize + 17, application_info, 32);
    memcpy(format.raw() + SecondStageMACDigestSize + 49, user_info, 16);
    memcpy(format.raw() + SecondStageMACDigestSize + 65, additional_info, 16);
    return format;
}

template <size_t SecondStageMACDigestSize>
inline static SecureBuffer<SecondStageMACDigestSize + 81> &updateFormat(
    SecureBuffer<SecondStageMACDigestSize + 81> &format,
    const SecureBuffer<SecondStageMACDigestSize> &current_state,
    uint64_t counter
) {
    counter = htole64(counter);
    memcpy(format.raw() + 1, &counter, 8);
    std::copy(
        current_state.begin(),
        current_state.end(),
        format.begin() + 9
    );
    return format;
}

template<
    FirstStageVariants FirstStageVariant,
    SecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
void KDF_R_13235651022<
FirstStageVariant, SecondStageVariant,
MasterKeySize, SaltSize
>::fetch(
    uint8_t *key, const uint64_t size,
    const uint8_t (&IV)[SecondStageMACDigestSize],
    const uint8_t (&application_info)[32],
    const uint8_t (&user_info)[16],
    const uint8_t (&additional_info)[16]
) noexcept {
    SecureBuffer<SecondStageMACDigestSize + 81> format =
        getFormat(IV, application_info, user_info, additional_info, size);
    SecureBuffer<SecondStageMACDigestSize> current_state;
    const size_t full_blocks = size / SecondStageMACDigestSize;
    const size_t remainder = size % SecondStageMACDigestSize;
    for (size_t counter = 0; counter < full_blocks; ++counter) {
        second_stage_macer_->update(format.raw(), SecondStageMACDigestSize + 81);
        second_stage_macer_->digest(current_state.raw());
        second_stage_macer_->clear();
        memcpy(key + counter * SecondStageMACDigestSize, current_state.raw(), SecondStageMACDigestSize);
        updateFormat(format, current_state, counter + 2);
    }
    if (remainder > 0) {
        second_stage_macer_->update(format.raw(), SecondStageMACDigestSize + 81);
        second_stage_macer_->digest(current_state.raw());
        memcpy(key + (size - remainder), current_state.raw(), remainder);
    }
    second_stage_macer_->clear();
}

#endif