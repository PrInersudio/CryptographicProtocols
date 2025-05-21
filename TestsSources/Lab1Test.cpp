#include <benchmark/benchmark.h>
#include <fstream>
#include <random>
#include "SecureBuffer.hpp"
#include "Utils.hpp"
#include "OMAC.hpp"
#include "OpenSSLKuznechikOMAC.hpp"

#define TestFilesFolder "../TestsData/"

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

static void ConstKey_MB1(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1MB.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MB.bin.");
        OMAC<Kuznechik> ctx;
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        ctx.digest();
    }
    state.SetBytesProcessed(state.iterations() * (1 << 20));
}
BENCHMARK(ConstKey_MB1);

static void ConstKey_MB100(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "100MB.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "100MB.bin.");
        OMAC<Kuznechik> ctx;
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        ctx.digest();
    }
    state.SetBytesProcessed(state.iterations() * (1 << 20) * 100);
}
BENCHMARK(ConstKey_MB100);

static void ConstKey_MB1000(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1000MB.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть" TestFilesFolder "1000MB.bin.");
        OMAC<Kuznechik> ctx;
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        ctx.digest();
    }
    state.SetBytesProcessed(state.iterations() * (1 << 20) * 1000);
}
BENCHMARK(ConstKey_MB1000);

static void VariableKey_Blocks10(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1MBlocks.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MBlocks.bin.");
        std::vector<uint8_t> buf(160);
        for (uint32_t i = 0; i < 100000; ++i) {
            OMAC<Kuznechik> ctx(RandKeyGenerator::genRandKey());
            file.read(reinterpret_cast<char *>(buf.data()), 160);
            ctx.update(buf);
            ctx.digest();
        }
    }
    state.SetBytesProcessed(state.iterations() * 16000000);
}
BENCHMARK(VariableKey_Blocks10);

static void VariableKey_Blocks100(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1MBlocks.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MBlocks.bin.");
        std::vector<uint8_t> buf(1600);
        for (uint32_t i = 0; i < 10000; ++i) {
            OMAC<Kuznechik> ctx(RandKeyGenerator::genRandKey());
            file.read(reinterpret_cast<char *>(buf.data()), 1600);
            ctx.update(buf);
            ctx.digest();
        }
    }
    state.SetBytesProcessed(state.iterations() * 16000000);
}
BENCHMARK(VariableKey_Blocks100);

static void VariableKey_Blocks1000(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1MBlocks.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MBlocks.bin.");
        std::vector<uint8_t> buf(16000);
        for (uint32_t i = 0; i < 1000; ++i) {
            OMAC<Kuznechik> ctx(RandKeyGenerator::genRandKey());
            file.read(reinterpret_cast<char *>(buf.data()), 16000);
            ctx.update(buf);
            ctx.digest();
        }
    }
    state.SetBytesProcessed(state.iterations() * 16000000);
}
BENCHMARK(VariableKey_Blocks1000);

static void OpenSSLConstKey_MB1(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1MB.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "1MB.bin.");
        OpenSSLKuznechikOMAC ctx(key);
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        const std::vector<uint8_t> mac = ctx.digest();
    }
    state.SetBytesProcessed(state.iterations() * (1 << 20));
}
BENCHMARK(OpenSSLConstKey_MB1);

static void OpenSSLConstKey_MB100(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "100MB.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder "100MB.bin.");
        OpenSSLKuznechikOMAC ctx(key);
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        const std::vector<uint8_t> mac = ctx.digest();
    }
    state.SetBytesProcessed(state.iterations() * (1 << 20) * 100);
}
BENCHMARK(OpenSSLConstKey_MB100);

static void OpenSSLConstKey_MB1000(benchmark::State& state) {
    for (auto _ : state) {
        std::ifstream file(TestFilesFolder "1000MB.bin", std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть" TestFilesFolder "1000MB.bin.");
        OpenSSLKuznechikOMAC ctx(key);
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        const std::vector<uint8_t> mac = ctx.digest();
    }
    state.SetBytesProcessed(state.iterations() * (1 << 20) * 1000);
}
BENCHMARK(OpenSSLConstKey_MB1000);

static void OpenSSLVariableKey_Blocks10(benchmark::State& state) {
    for (auto _ : state) {
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
    state.SetBytesProcessed(state.iterations() * 16000000);
}
BENCHMARK(OpenSSLVariableKey_Blocks10);

static void OpenSSLVariableKey_Blocks100(benchmark::State& state) {
    for (auto _ : state) {
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
    state.SetBytesProcessed(state.iterations() * 16000000);
}
BENCHMARK(OpenSSLVariableKey_Blocks100);

static void OpenSSLVariableKey_Blocks1000(benchmark::State& state) {
    for (auto _ : state) {
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
    state.SetBytesProcessed(state.iterations() * 16000000);
}
BENCHMARK(OpenSSLVariableKey_Blocks1000);

BENCHMARK_MAIN();