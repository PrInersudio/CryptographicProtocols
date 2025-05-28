#ifndef CRYPTOGRAPHIC_SUITES_HPP
#define CRYPTOGRAPHIC_SUITES_HPP

#include <cinttypes>
#include <cstddef>
#include <stdexcept>

enum class CryptographicSuites : uint8_t {
    NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC,
    NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256,
    NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512,
    NULL_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC,
    NULL_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC,
    NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256,
    NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512,
    NULL_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC,
    NULL_KuznechikCMAC_256_128_R13235651022_Simple_NMAC,
    NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256,
    NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512,
    NULL_KuznechikCMAC_256_128_R13235651022_Simple_CMAC,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_NMAC,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512,
    KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_CMAC
};

constexpr size_t getICVLength(const CryptographicSuites cryptographic_suite) {
    switch (cryptographic_suite) {
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
            return 48;
        default:
            throw std::invalid_argument("Данный криптографический набор не поддерживается.");
    }
}

#endif