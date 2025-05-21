#ifndef OPENSSLKDF_R_13235651022_HPP
#define OPENSSLKDF_R_13235651022_HPP

#include <endian.h>
#include <memory>
#include "OpenSSLStreebog256HMAC.hpp"
#include "OpenSSLStreebog512HMAC.hpp"
#include "OpenSSLNMAC256.hpp"
#include "OpenSSLKuznechikOMAC.hpp"

enum class OpenSSLFirstStageVariants { NMAC = 0, HMAC = 1, Simple = 2 };
enum class OpenSSLSecondStageVariants { NMAC = 0, HMAC256 = 1, HMAC512 = 2, CMAC = 3 };

template <OpenSSLSecondStageVariants V>
struct OpenSSLSecondStageMACParams;

template <>
struct OpenSSLSecondStageMACParams<OpenSSLSecondStageVariants::NMAC> {
    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 32;
};

template <>
struct OpenSSLSecondStageMACParams<OpenSSLSecondStageVariants::HMAC256> {
    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 32;
};

template <>
struct OpenSSLSecondStageMACParams<OpenSSLSecondStageVariants::HMAC512> {
    static constexpr size_t BlockSize = 64;
    static constexpr size_t DigestSize = 64;
};

template <>
struct OpenSSLSecondStageMACParams<OpenSSLSecondStageVariants::CMAC> {
    static constexpr size_t BlockSize = 16;
    static constexpr size_t DigestSize = 16;
};

template <
    OpenSSLFirstStageVariants FirstStageVariant,
    OpenSSLSecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
class OpenSSLKDF_R_13235651022 {
private:
    static constexpr size_t SecondStageMACBlockSize = OpenSSLSecondStageMACParams<SecondStageVariant>::BlockSize;
    static constexpr size_t SecondStageMACDigestSize = OpenSSLSecondStageMACParams<SecondStageVariant>::DigestSize;
    std::unique_ptr<MAC<SecondStageMACBlockSize, SecondStageMACDigestSize, 32>> second_stage_macer_;

    static void firstStage(
        SecureBuffer<32> &inner_key,
        const SecureBuffer<MasterKeySize> &master_key,
        const SecureBuffer<SaltSize> &salt
    ) noexcept;
    void initSecondStageMacer(SecureBuffer<32> &inner_key) noexcept;
public:
    OpenSSLKDF_R_13235651022(
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
    OpenSSLFirstStageVariants FirstStageVariant,
    OpenSSLSecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
void OpenSSLKDF_R_13235651022<
FirstStageVariant, SecondStageVariant,
MasterKeySize, SaltSize
>::firstStage(
    SecureBuffer<32> &inner_key,
    const SecureBuffer<MasterKeySize> &master_key,
    const SecureBuffer<SaltSize> &salt
) noexcept {
    if constexpr (FirstStageVariant == OpenSSLFirstStageVariants::NMAC) {
        OpenSSLNMAC256<SaltSize> macer(salt);
        macer.update(master_key.raw(), MasterKeySize);
        macer.digest(inner_key.raw());
    }
    else if constexpr (FirstStageVariant == OpenSSLFirstStageVariants::HMAC) {
        OpenSSLStreebog512HMAC<SaltSize> macer(salt);
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
    OpenSSLFirstStageVariants FirstStageVariant,
    OpenSSLSecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
void OpenSSLKDF_R_13235651022<
    FirstStageVariant, SecondStageVariant,
    MasterKeySize, SaltSize
>::initSecondStageMacer(SecureBuffer<32> &inner_key) noexcept {
    if constexpr (SecondStageVariant == OpenSSLSecondStageVariants::NMAC)
        second_stage_macer_ = std::make_unique<OpenSSLNMAC256<32>>(inner_key);
    else if constexpr (SecondStageVariant == OpenSSLSecondStageVariants::HMAC256)
        second_stage_macer_ = std::make_unique<OpenSSLStreebog256HMAC<32>>(inner_key);
    else if constexpr (SecondStageVariant == OpenSSLSecondStageVariants::HMAC512)
        second_stage_macer_ = std::make_unique<OpenSSLStreebog512HMAC<32>>(inner_key);
    else second_stage_macer_ = std::make_unique<OpenSSLKuznechikOMAC>(inner_key);
}

template <
    OpenSSLFirstStageVariants FirstStageVariant,
    OpenSSLSecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
OpenSSLKDF_R_13235651022<
    FirstStageVariant, SecondStageVariant,
    MasterKeySize, SaltSize
>::OpenSSLKDF_R_13235651022(
    const SecureBuffer<MasterKeySize> &master_key,
    const SecureBuffer<SaltSize> &salt
) noexcept {
    SecureBuffer<32> inner_key;
    firstStage(inner_key, master_key, salt);
    initSecondStageMacer(inner_key);
}

template <size_t SecondStageMACDigestSize>
inline static SecureBuffer<SecondStageMACDigestSize + 81> OpenSSLgetFormat(
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
inline static SecureBuffer<SecondStageMACDigestSize + 81> &OpenSSLupdateFormat(
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
    OpenSSLFirstStageVariants FirstStageVariant,
    OpenSSLSecondStageVariants SecondStageVariant,
    size_t MasterKeySize,
    size_t SaltSize
>
void OpenSSLKDF_R_13235651022<
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
        OpenSSLgetFormat(IV, application_info, user_info, additional_info, size);
    SecureBuffer<SecondStageMACDigestSize> current_state;
    const size_t full_blocks = size / SecondStageMACDigestSize;
    const size_t remainder = size % SecondStageMACDigestSize;
    for (size_t counter = 0; counter < full_blocks; ++counter) {
        second_stage_macer_->update(format.raw(), SecondStageMACDigestSize + 81);
        second_stage_macer_->digest(current_state.raw());
        second_stage_macer_->clear();
        memcpy(key + counter * SecondStageMACDigestSize, current_state.raw(), SecondStageMACDigestSize);
        OpenSSLupdateFormat(format, current_state, counter + 2);
    }
    if (remainder > 0) {
        second_stage_macer_->update(format.raw(), SecondStageMACDigestSize + 81);
        second_stage_macer_->digest(current_state.raw());
        memcpy(key + (size - remainder), current_state.raw(), remainder);
    }
    second_stage_macer_->clear();
}

#endif