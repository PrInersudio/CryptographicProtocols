#include <gtest/gtest.h>
#include <fstream>
#ifndef UNIT_TESTS
#define UNIT_TESTS
#endif
#include "Utils.hpp"

TEST(CheckTimestampTest, ValidTimestamp) {
    testing::internal::CaptureStdout();
    const uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        (std::chrono::system_clock::now() - std::chrono::years(1)).time_since_epoch()
    ).count());
    checkTimestamp(timestamp);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Срок действия ключа подходит к концу!"), std::string::npos);
}

TEST(CheckTimestampTest, ExpiredTimestamp) {
    testing::internal::CaptureStdout();
    const uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        (std::chrono::system_clock::now() - std::chrono::years(1) - std::chrono::months(6)).time_since_epoch()
    ).count());
    checkTimestamp(timestamp);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Срок действия ключа подошёл к концу!"), std::string::npos);
}

TEST(CheckTimestampTest, ValidKey) {
    testing::internal::CaptureStdout();
    uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());
    checkTimestamp(timestamp);
    std::string output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("Проверка срока действия ключа прошла успешно."), std::string::npos);
}

TEST(InitKuznechikCTXTest, FileReadSuccess) {
    std::ofstream file("test_key.bin", std::ios::binary);
    uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        (std::chrono::system_clock::now() - std::chrono::years(1)).time_since_epoch()
    ).count());
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    timestamp = __builtin_bswap64(timestamp);
    #endif
    file.write(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
    static SecureBuffer key = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    file.write(reinterpret_cast<char*>(key.raw()), 32);
    file.close();
    OMAC<Kuznechik> ctx;
    EXPECT_NO_THROW(initKuznechikOMACCTX(ctx, "test_key.bin"));
    static const SecureBuffer<16> round_keys[] = {
        { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
        { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
        { 0xdb, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43, 0x22, 0x8d, 0x6a, 0xef, 0x8c, 0xc7, 0x8c, 0x44 },
        { 0x3d, 0x45, 0x53, 0xd8, 0xe9, 0xcf, 0xec, 0x68, 0x15, 0xeb, 0xad, 0xc4, 0x0a, 0x9f, 0xfd, 0x04 },
        { 0x57, 0x64, 0x64, 0x68, 0xc4, 0x4a, 0x5e, 0x28, 0xd3, 0xe5, 0x92, 0x46, 0xf4, 0x29, 0xf1, 0xac },
        { 0xbd, 0x07, 0x94, 0x35, 0x16, 0x5c, 0x64, 0x32, 0xb5, 0x32, 0xe8, 0x28, 0x34, 0xda, 0x58, 0x1b },
        { 0x51, 0xe6, 0x40, 0x75, 0x7e, 0x87, 0x45, 0xde, 0x70, 0x57, 0x27, 0x26, 0x5a, 0x00, 0x98, 0xb1 },
        { 0x5a, 0x79, 0x25, 0x01, 0x7b, 0x9f, 0xdd, 0x3e, 0xd7, 0x2a, 0x91, 0xa2, 0x22, 0x86, 0xf9, 0x84 },
        { 0xbb, 0x44, 0xe2, 0x53, 0x78, 0xc7, 0x31, 0x23, 0xa5, 0xf3, 0x2f, 0x73, 0xcd, 0xb6, 0xe5, 0x17 },
        { 0x72, 0xe9, 0xdd, 0x74, 0x16, 0xbc, 0xf4, 0x5b, 0x75, 0x5d, 0xba, 0xa8, 0x8e, 0x4a, 0x40, 0x43 }
    };
    const SecureBuffer<16> *result_round_keys = ctx.getCipherCTX().getKeySchedule();
    for (uint8_t i = 0; i < 10; ++i)
        EXPECT_EQ(round_keys[i], result_round_keys[i]) << "Не совпал ключ " << i;
    remove("test_key.bin");
}

TEST(InitKuznechikCTXTest, FileReadFailure) {
    OMAC<Kuznechik> ctx;
    EXPECT_THROW(initKuznechikOMACCTX(ctx, "non_existent_file.bin"), std::runtime_error);
}

TEST(InitKuznechikCTXTest, FileHasNotEnouthForTimestamp) {
    std::ofstream file("test_key.bin", std::ios::binary);
    static constexpr char test_fill[] = {0x0, 0x1, 0x2, 0x3};
    file.write(test_fill, 4);
    file.close();
    OMAC<Kuznechik> ctx;
    EXPECT_THROW(initKuznechikOMACCTX(ctx, "test_key.bin"), std::runtime_error);
    remove("test_key.bin");
}

TEST(InitKuznechikCTXTest, FileHasNotEnouthForKey) {
    std::ofstream file("test_key.bin", std::ios::binary);
    static constexpr char test_fill[] = {0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3};
    file.write(test_fill, 4);
    file.close();
    OMAC<Kuznechik> ctx;
    EXPECT_THROW(initKuznechikOMACCTX(ctx, "test_key.bin"), std::runtime_error);
    remove("test_key.bin");
}

TEST(ParseHexStringTest, ValidHex) {
    std::vector<uint8_t> expected = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(parseHexString("DEADBEEF"), expected);
}

TEST(ParseHexStringTest, ValidHexLowercase) {
    std::vector<uint8_t> expected = {0x0A, 0x0B, 0x0C, 0x0D};
    EXPECT_EQ(parseHexString("0a0b0c0d"), expected);
}

TEST(ParseHexStringTest, InvalidLength) {
    EXPECT_THROW(parseHexString("ABC"), std::invalid_argument);
}

TEST(ParseHexStringTest, InvalidCharacters) {
    EXPECT_THROW(parseHexString("GG"), std::invalid_argument);
}

TEST(ToHexStringTest, EmptyVector) {
    std::vector<uint8_t> data = {};
    EXPECT_EQ(toHexString(data), "");
}

TEST(ToHexStringTest, SingleByte) {
    std::vector<uint8_t> data = {0xAB};
    EXPECT_EQ(toHexString(data), "ab");
}

TEST(ToHexStringTest, MultipleBytes) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(toHexString(data), "deadbeef");
}

TEST(ToHexStringTest, LeadingZero) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    EXPECT_EQ(toHexString(data), "010203");
}

TEST(ToHexStringTest, AllZeroes) {
    std::vector<uint8_t> data(5, 0x00); // 5 нулей
    EXPECT_EQ(toHexString(data), "0000000000");
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}