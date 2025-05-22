#ifndef KDF_R_13235651022_HPP
#define KDF_R_13235651022_HPP

#include <endian.h>
#include <memory>
#include "Hash.hpp"

template <IsMAC InnerMAC, IsMAC OuterMAC, size_t MasterKeySize>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
class KDF_R_13235651022 {
private:
    OuterMAC outer_mac_;
public:
    KDF_R_13235651022() = default;
    void init(
        const SecureBuffer<MasterKeySize> &master_key,
        const SecureBuffer<InnerMAC::KeySize> &salt
    ) noexcept;
    inline KDF_R_13235651022(
        const SecureBuffer<MasterKeySize> &master_key,
        const SecureBuffer<InnerMAC::KeySize> &salt
    ) noexcept { init(master_key, salt); }
    void fetch(
        uint8_t *key, const uint64_t size,
        const uint8_t (&IV)[OuterMAC::DigestSize],
        const uint8_t (&application_info)[32],
        const uint8_t (&user_info)[16],
        const uint8_t (&additional_info)[16]
    ) noexcept;
};

template <IsMAC InnerMAC, IsMAC OuterMAC, size_t MasterKeySize>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
void KDF_R_13235651022<InnerMAC, OuterMAC, MasterKeySize>::init(
    const SecureBuffer<MasterKeySize> &master_key,
    const SecureBuffer<InnerMAC::KeySize> &salt
) noexcept {
    SecureBuffer<OuterMAC::KeySize> inner_key;
    InnerMAC mac(salt);
    mac.update(master_key.raw(), MasterKeySize);
    if constexpr (InnerMAC::DigestSize == OuterMAC::KeySize) mac.digest(inner_key.raw());
    else {
        SecureBuffer<InnerMAC::DigestSize> big_inner_key;
        mac.digest(big_inner_key.raw());
        std::copy(big_inner_key.begin(), big_inner_key.begin() + OuterMAC::KeySize, inner_key.begin());
    }
    outer_mac_.initKeySchedule(inner_key);
}

template <size_t DigestSize>
inline static SecureBuffer<DigestSize + 81> getFormat(
    const uint8_t (&IV)[DigestSize],
    const uint8_t (&application_info)[32],
    const uint8_t (&user_info)[16],
    const uint8_t (&additional_info)[16],
    uint64_t size
) {
    SecureBuffer<DigestSize + 81> format;
    format[0] = 0xFC;
    uint64_t counter = htole64(1);
    memcpy(format.raw() + 1, &counter, 8);
    memcpy(format.raw() + 9, IV, DigestSize);
    size = htole64(size * 8);
    memcpy(format.raw() + DigestSize + 9, &size, 8);
    memcpy(format.raw() + DigestSize + 17, application_info, 32);
    memcpy(format.raw() + DigestSize + 49, user_info, 16);
    memcpy(format.raw() + DigestSize + 65, additional_info, 16);
    return format;
}

template <size_t DigestSize>
inline static SecureBuffer<DigestSize + 81> &updateFormat(
    SecureBuffer<DigestSize + 81> &format,
    const SecureBuffer<DigestSize> &current_state,
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

template <IsMAC InnerMAC, IsMAC OuterMAC, size_t MasterKeySize>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
void KDF_R_13235651022<InnerMAC, OuterMAC, MasterKeySize>::fetch(
    uint8_t *key, const uint64_t size,
    const uint8_t (&IV)[OuterMAC::DigestSize],
    const uint8_t (&application_info)[32],
    const uint8_t (&user_info)[16],
    const uint8_t (&additional_info)[16]
) noexcept {
    SecureBuffer<OuterMAC::DigestSize + 81> format =
        getFormat(IV, application_info, user_info, additional_info, size);
    SecureBuffer<OuterMAC::DigestSize> current_state;
    const size_t full_blocks = size / OuterMAC::DigestSize;
    const size_t remainder = size % OuterMAC::DigestSize;
    for (size_t counter = 0; counter < full_blocks; ++counter) {
        outer_mac_.update(format.raw(), OuterMAC::DigestSize + 81);
        outer_mac_.digest(current_state.raw());
        outer_mac_.clear();
        memcpy(key + counter * OuterMAC::DigestSize, current_state.raw(), OuterMAC::DigestSize);
        updateFormat(format, current_state, counter + 2);
    }
    if (remainder > 0) {
        outer_mac_.update(format.raw(), OuterMAC::DigestSize + 81);
        outer_mac_.digest(current_state.raw());
        memcpy(key + (size - remainder), current_state.raw(), remainder);
    }
    outer_mac_.clear();
}

#endif