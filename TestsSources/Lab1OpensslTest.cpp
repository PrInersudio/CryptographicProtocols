#include <gtest/gtest.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <fstream>
#include <random>
#include "SecureBuffer.hpp"
#include "Lab1Utils.hpp"

#define TestFilesFolder "../Lab1TestsData/"

class OpenSSLKuznechikOMAC {
private:
    EVP_MAC_CTX* ctx_;
    EVP_MAC* mac_;
public:
    OpenSSLKuznechikOMAC(const SecureBuffer<32> &key);
    ~OpenSSLKuznechikOMAC();
    void update(const std::vector<uint8_t> &data);
    std::vector<uint8_t> digest(const size_t size = 16);
};

OpenSSLKuznechikOMAC::OpenSSLKuznechikOMAC(const SecureBuffer<32> &key) {
    mac_ = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    if (!mac_) throw std::runtime_error("Не удалось получить MAC CMAC.");
    ctx_ = EVP_MAC_CTX_new(mac_);
    if (!ctx_) {
        EVP_MAC_free(mac_);
        throw std::runtime_error("Не удалось создать MAC контекст.");
    }
    char cipher_name[] = "kuznyechik-cbc";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("cipher", cipher_name, 0),
        OSSL_PARAM_END
    };
    if (!EVP_MAC_init(ctx_, key.raw(), 32, params)) {
        EVP_MAC_CTX_free(ctx_);
        EVP_MAC_free(mac_);
        throw std::runtime_error("Ошибка инициализации CMAC.");
    }
}

OpenSSLKuznechikOMAC::~OpenSSLKuznechikOMAC() {
    EVP_MAC_CTX_free(ctx_);
    EVP_MAC_free(mac_);
}

void OpenSSLKuznechikOMAC::update(const std::vector<uint8_t> &data) {
    if (!EVP_MAC_update(ctx_, data.data(), data.size()))
        throw std::runtime_error("Ошибка обновления CMAC.");
}

std::vector<uint8_t> OpenSSLKuznechikOMAC::digest(const size_t size) {
    uint8_t out[EVP_MAX_MD_SIZE];
    size_t out_len = 0;
    if (!EVP_MAC_final(ctx_, out, &out_len, sizeof(out)))
        throw std::runtime_error("Ошибка получения финального значения CMAC.");
    if (size > out_len)
        throw std::out_of_range("Размер MAC превышает допустимый.");
    return std::vector<uint8_t>(out, out + size);
}

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

static const SecureBuffer key = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

TEST(ConstKey, MB1) {
    std::ifstream file(TestFilesFolder "1MB.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MB.bin.");
    OpenSSLKuznechikOMAC ctx(key);
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    const std::vector<uint8_t> mac = ctx.digest();
}

TEST(ConstKey, MB100) {
    std::ifstream file(TestFilesFolder "100MB.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "100MB.bin.");
    OpenSSLKuznechikOMAC ctx(key);
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    const std::vector<uint8_t> mac = ctx.digest();
}

TEST(ConstKey, MB1000) {
    std::ifstream file(TestFilesFolder "1000MB.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть" TestFilesFolder "1000MB.bin.");
    OpenSSLKuznechikOMAC ctx(key);
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    const std::vector<uint8_t> mac = ctx.digest();
}

TEST(VariableKey, Blocks10) {
    std::ifstream file(TestFilesFolder "1MBlocks.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MBlocks.bin.");
    std::vector<uint8_t> buf(160);
    for (uint32_t i = 0; i < 100000; ++i) {
        OpenSSLKuznechikOMAC ctx(RandKeyGenerator::genRandKey());
        file.read(reinterpret_cast<char *>(buf.data()), 160);
        ctx.update(buf);
        ctx.digest();
    }
}

TEST(VariableKey, Blocks100) {
    std::ifstream file(TestFilesFolder "1MBlocks.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MBlocks.bin.");
    std::vector<uint8_t> buf(1600);
    for (uint32_t i = 0; i < 10000; ++i) {
        OpenSSLKuznechikOMAC ctx(RandKeyGenerator::genRandKey());
        file.read(reinterpret_cast<char *>(buf.data()), 1600);
        ctx.update(buf);
        ctx.digest();
    }
}

TEST(VariableKey, Blocks1000) {
    std::ifstream file(TestFilesFolder "1MBlocks.bin", std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MBlocks.bin.");
    std::vector<uint8_t> buf(16000);
    for (uint32_t i = 0; i < 1000; ++i) {
        OpenSSLKuznechikOMAC ctx(RandKeyGenerator::genRandKey());
        file.read(reinterpret_cast<char *>(buf.data()), 16000);
        ctx.update(buf);
        ctx.digest();
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}