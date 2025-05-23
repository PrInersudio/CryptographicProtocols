#include "CryptographicSuites.hpp"

size_t getICVLength(const CryptographicSuites cryptographic_suite) {
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
            throw std::invalid_argument("Поддержка данного криптонабора не имплементирована.");
    }
}