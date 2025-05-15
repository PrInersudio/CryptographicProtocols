#include <benchmark/benchmark.h>
#include "KDF_R_13235651022.hpp"
#include "OpenSSLKDF_R_13235651022.hpp"

template<size_t N>
static SecureBuffer<N> filled(uint8_t val) {
    SecureBuffer<N> buf;
    std::fill(buf.begin(), buf.end(), val);
    return buf;
}

void KDF_R_13235651022_FirstNMACSecondNMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[32];
    memset(IV, 0xCC, 32);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::NMAC,
        SecondStageVariants::NMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstNMACSecondNMAC);

void KDF_R_13235651022_FirstNMACSecondHMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[64];
    memset(IV, 0xCC, 64);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::NMAC,
        SecondStageVariants::HMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstNMACSecondHMAC);

void KDF_R_13235651022_FirstNMACSecondCMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[16];
    memset(IV, 0xCC, 16);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::NMAC,
        SecondStageVariants::CMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstNMACSecondCMAC);

void KDF_R_13235651022_FirstHMACSecondNMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[32];
    memset(IV, 0xCC, 32);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::HMAC,
        SecondStageVariants::NMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstHMACSecondNMAC);

void KDF_R_13235651022_FirstHMACSecondHMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[64];
    memset(IV, 0xCC, 64);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::HMAC,
        SecondStageVariants::HMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstHMACSecondHMAC);

void KDF_R_13235651022_FirstHMACSecondCMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[16];
    memset(IV, 0xCC, 16);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::HMAC,
        SecondStageVariants::CMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstHMACSecondCMAC);

void KDF_R_13235651022_FirstSimpleSecondNMAC(benchmark::State& state) {
    static const SecureBuffer<32> master_key = filled<32>(0xAA);
    static const SecureBuffer<32> salt = filled<32>(0xBB);
    uint8_t IV[32];
    memset(IV, 0xCC, 32);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::Simple,
        SecondStageVariants::NMAC,
        32, 32
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstSimpleSecondNMAC);

void KDF_R_13235651022_FirstSimpleSecondHMAC(benchmark::State& state) {
    static const SecureBuffer<32> master_key = filled<32>(0xAA);
    static const SecureBuffer<32> salt = filled<32>(0xBB);
    uint8_t IV[64];
    memset(IV, 0xCC, 64);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::Simple,
        SecondStageVariants::HMAC,
        32, 32
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstSimpleSecondHMAC);

void KDF_R_13235651022_FirstSimpleSecondCMAC(benchmark::State& state) {
    static const SecureBuffer<32> master_key = filled<32>(0xAA);
    static const SecureBuffer<32> salt = filled<32>(0xBB);
    uint8_t IV[16];
    memset(IV, 0xCC, 16);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    KDF_R_13235651022<
        FirstStageVariants::Simple,
        SecondStageVariants::CMAC,
        32, 32
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_FirstSimpleSecondCMAC);

void KDF_R_13235651022_OpenSSLFirstNMACSecondNMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[32];
    memset(IV, 0xCC, 32);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::NMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstNMACSecondNMAC);

void KDF_R_13235651022_OpenSSLFirstNMACSecondHMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[64];
    memset(IV, 0xCC, 64);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::HMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstNMACSecondHMAC);

void KDF_R_13235651022_OpenSSLFirstNMACSecondCMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[16];
    memset(IV, 0xCC, 16);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::CMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstNMACSecondCMAC);

void KDF_R_13235651022_OpenSSLFirstHMACSecondNMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[32];
    memset(IV, 0xCC, 32);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::NMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstHMACSecondNMAC);

void KDF_R_13235651022_OpenSSLFirstHMACSecondHMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[64];
    memset(IV, 0xCC, 64);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::HMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstHMACSecondHMAC);

void KDF_R_13235651022_OpenSSLFirstHMACSecondCMAC(benchmark::State& state) {
    static const SecureBuffer<128> master_key = filled<128>(0xAA);
    static const SecureBuffer<128> salt = filled<128>(0xBB);
    uint8_t IV[16];
    memset(IV, 0xCC, 16);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::CMAC,
        128, 128
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstHMACSecondCMAC);

void KDF_R_13235651022_OpenSSLFirstSimpleSecondNMAC(benchmark::State& state) {
    static const SecureBuffer<32> master_key = filled<32>(0xAA);
    static const SecureBuffer<32> salt = filled<32>(0xBB);
    uint8_t IV[32];
    memset(IV, 0xCC, 32);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::NMAC,
        32, 32
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstSimpleSecondNMAC);

void KDF_R_13235651022_OpenSSLFirstSimpleSecondHMAC(benchmark::State& state) {
    static const SecureBuffer<32> master_key = filled<32>(0xAA);
    static const SecureBuffer<32> salt = filled<32>(0xBB);
    uint8_t IV[64];
    memset(IV, 0xCC, 64);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::HMAC,
        32, 32
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstSimpleSecondHMAC);

void KDF_R_13235651022_OpenSSLFirstSimpleSecondCMAC(benchmark::State& state) {
    static const SecureBuffer<32> master_key = filled<32>(0xAA);
    static const SecureBuffer<32> salt = filled<32>(0xBB);
    uint8_t IV[16];
    memset(IV, 0xCC, 16);
    uint8_t application_info[32];
    memset(application_info, 0xDD, 32);
    uint8_t user_info[16];
    memset(user_info, 0xEE, 16);
    uint8_t additional_info[16];
    memset(additional_info, 0xFF, 16);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::CMAC,
        32, 32
    > kdf(master_key, salt);
    for (auto _ : state) {
        uint8_t keys[32000000];
        kdf.fetch(keys, 32000000, IV, application_info, user_info, additional_info);
    }
}
BENCHMARK(KDF_R_13235651022_OpenSSLFirstSimpleSecondCMAC);

BENCHMARK_MAIN();