#include <gtest/gtest.h>
#include <iomanip>
#include "KDF_R_13235651022.hpp"
#include "OpenSSLKDF_R_13235651022.hpp"

template <size_t N>
void PrintTo(const SecureBuffer<N> &buf, std::ostream* os) {
    *os << std::hex << std::uppercase << std::setfill('0');
    for (uint8_t byte : buf)
        *os << std::setw(2) << static_cast<int>(byte);
}

template<size_t N>
static SecureBuffer<N> filled(uint8_t val) {
    SecureBuffer<N> buf;
    std::fill(buf.begin(), buf.end(), val);
    return buf;
}

TEST(KDF_R_13235651022Test, TestFirstNMACSecondNMAC) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::NMAC,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstNMACSecondHMAC256) {
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
        SecondStageVariants::HMAC256,
        128, 128
    > kdf(master_key, salt);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::HMAC256,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstNMACSecondHMAC512) {
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
        SecondStageVariants::HMAC512,
        128, 128
    > kdf(master_key, salt);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::HMAC512,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstNMACSecondCMAC) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::CMAC,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstHMACSecondNMAC) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::NMAC,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstHMACSecondHMAC256) {
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
        SecondStageVariants::HMAC256,
        128, 128
    > kdf(master_key, salt);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::HMAC256,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstHMACSecondHMAC512) {
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
        SecondStageVariants::HMAC512,
        128, 128
    > kdf(master_key, salt);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::HMAC512,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstHMACSecondCMAC) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::HMAC,
        OpenSSLSecondStageVariants::CMAC,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstSimpleSecondNMAC) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::NMAC,
        32, 32
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstSimpleSecondHMAC256) {
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
        SecondStageVariants::HMAC256,
        32, 32
    > kdf(master_key, salt);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::HMAC256,
        32, 32
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstSimpleSecondHMAC512) {
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
        SecondStageVariants::HMAC512,
        32, 32
    > kdf(master_key, salt);
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::HMAC512,
        32, 32
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestFirstSimpleSecondCMAC) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::Simple,
        OpenSSLSecondStageVariants::CMAC,
        32, 32
    > openssl_kdf(master_key, salt);
    SecureBuffer<256> key1;
    SecureBuffer<256> key2;
    kdf.fetch(key1.raw(), 256, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 256, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestKeyLengthWithRemainder) {
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
    OpenSSLKDF_R_13235651022<
        OpenSSLFirstStageVariants::NMAC,
        OpenSSLSecondStageVariants::NMAC,
        128, 128
    > openssl_kdf(master_key, salt);
    SecureBuffer<250> key1;
    SecureBuffer<250> key2;
    kdf.fetch(key1.raw(), 250, IV, application_info, user_info, additional_info);
    openssl_kdf.fetch(key2.raw(), 250, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

TEST(KDF_R_13235651022Test, TestDoubleUse) {
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
    SecureBuffer<250> key1;
    SecureBuffer<250> key2;
    kdf.fetch(key1.raw(), 250, IV, application_info, user_info, additional_info);
    kdf.fetch(key2.raw(), 250, IV, application_info, user_info, additional_info);
    std::cout << "Key1: ";
    PrintTo(key1, &std::cout);
    std::cout << std::endl;
    std::cout << "Key2: ";
    PrintTo(key2, &std::cout);
    std::cout << std::endl;
    EXPECT_EQ(key1, key2);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}