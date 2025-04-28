/*  Ожидаемые значения получены через
    OpenSSL 3.4.1 11 Feb 2025 (Library: OpenSSL 3.4.1 11 Feb 2025) с
    openssl-gost-engine 3.0.3.r760.e0a500a-1
*/

#include <gtest/gtest.h>
#include <fstream>
#include <random>
#include "Kuznechik.hpp"
#include "OMAC.hpp"
#include "Lab1Utils.hpp"

#define TestFilesFolder "../Lab1TestsData/"

static const Kuznechik cipher({
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
});

namespace RandKeyGenerator {
    // Не криптостойкий ГСЧ используется только в рамках тестирования.
    SecureBuffer<32> genRandKey() {
        static std::mt19937 gen(std::random_device{}());
        static std::uniform_int_distribution<uint8_t> dist(0, 255);
        SecureBuffer<32> result;
        for (uint8_t &byte : result)
            byte = dist(gen);
        return result;
    }
}

TEST(ConstKey, MB1) {
    static const std::vector<uint8_t> expected_mac = {0x81, 0xC3, 0x97, 0xCC, 0x13, 0xE2, 0xAF, 0x68};
    std::ifstream file(TestFilesFolder "1MB.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MB.bin.");
    OMAC ctx(cipher);
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    const std::vector<uint8_t> mac = ctx.digest(expected_mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST(ConstKey, MB100) {
    static const std::vector<uint8_t> expected_mac = {0x74, 0xF0, 0xF8, 0xBD, 0xDD, 0xAC, 0xBD, 0xBE};
    std::ifstream file(TestFilesFolder "100MB.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "100MB.bin.");
    OMAC ctx(cipher);
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    const std::vector<uint8_t> mac = ctx.digest(expected_mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST(ConstKey, MB1000) {
    static const std::vector<uint8_t> expected_mac = {0x45, 0xE6, 0x9A, 0xB1, 0xD1, 0x86, 0x26, 0x03};
    std::ifstream file(TestFilesFolder "1000MB.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть" TestFilesFolder "1000MB.bin.");
    OMAC ctx(cipher);
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    const std::vector<uint8_t> mac = ctx.digest(expected_mac.size());
    EXPECT_EQ(mac, expected_mac);
}

TEST(VariableKey, Blocks10) {
    std::ifstream file(TestFilesFolder "16B_1M.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "16B_1M.bin.");
    std::vector<uint8_t> buf(160);
    for (uint32_t i = 0; i < 100000; ++i) {
        OMAC ctx(Kuznechik(RandKeyGenerator::genRandKey()));
        file.read(reinterpret_cast<char *>(buf.data()), 160);
        ctx.update(buf);
        ctx.digest();
    }
}

TEST(VariableKey, Blocks100) {
    std::ifstream file(TestFilesFolder "16B_1M.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "16B_1M.bin.");
    std::vector<uint8_t> buf(1600);
    for (uint32_t i = 0; i < 10000; ++i) {
        OMAC ctx(Kuznechik(RandKeyGenerator::genRandKey()));
        file.read(reinterpret_cast<char *>(buf.data()), 1600);
        ctx.update(buf);
        ctx.digest();
    }
}

TEST(VariableKey, Blocks1000) {
    std::ifstream file(TestFilesFolder "16B_1M.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "16B_1M.bin.");
    std::vector<uint8_t> buf(16000);
    for (uint32_t i = 0; i < 1000; ++i) {
        OMAC ctx(Kuznechik(RandKeyGenerator::genRandKey()));
        file.read(reinterpret_cast<char *>(buf.data()), 16000);
        ctx.update(buf);
        ctx.digest();
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}