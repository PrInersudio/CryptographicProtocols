#ifndef CRYPTOGRAPHIC_SUITES_HPP
#define CRYPTOGRAPHIC_SUITES_HPP

#include <cinttypes>
#include <cstddef>
#include <stdexcept>
#include <unordered_map>
#include "CRISPExceptions.hpp"

namespace CryptographicSuites {

    enum class ID : uint8_t {
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

    constexpr size_t getICVLength(const ID cryptographic_suite) {
        switch (cryptographic_suite) {
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
            case ID::NULL_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
            case ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
                return 48;
            default:
                throw crispex::invalid_argument("Данный криптографический набор не поддерживается.");
        }
    }

    inline const std::unordered_map<std::string, ID> &getAllSuites() {
        static const std::unordered_map<std::string, ID> suites = {
            #define ENUM_ENTRY(e) {#e, ID::e}
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_Simple_NMAC),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512),
            ENUM_ENTRY(NULL_KuznechikCMAC_256_128_R13235651022_Simple_CMAC),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_NMAC),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512),
            ENUM_ENTRY(KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_CMAC),
            #undef ENUM_ENTRY
        };
        return suites;
    }

    inline ID from_string(const std::string& name) {
        auto it = getAllSuites().find(name);
        if (it != getAllSuites().end()) {
            return it->second;
        }
        throw crispex::invalid_argument("Некорректное название криптонабора: " + name + ".");
    }

}

#endif