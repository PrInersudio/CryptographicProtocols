#include <benchmark/benchmark.h>
#include "Kuznechik.hpp"
#include "CTR_DRBG.hpp"

#define BUFFER_SIZE 65536
#define KEY_SIZE 32
#define TestFilesFolder "../TestsData/"

static void Random1MB(benchmark::State& state) {
    static constexpr std::string filename = "Random1M.bin";
    static constexpr size_t size = static_cast<size_t>(1) << 20;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        std::ofstream file(TestFilesFolder + filename, std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder + filename + ".");
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i) {
            rng(buffer, BUFFER_SIZE);
            file.write(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
            if (!file) throw std::runtime_error("Запись прервана после записи " + std::to_string(i * BUFFER_SIZE) + " байт.");
        }
        if constexpr (remainder > 0) {
            rng(buffer, remainder);
            file.write(reinterpret_cast<char *>(buffer), static_cast<std::streamsize>(remainder));
            if (!file)
                throw std::runtime_error("Запись прервана после записи "  + std::to_string(num_of_blocks * BUFFER_SIZE) + " байт.");
        }
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
    remove(filename.c_str());
}
BENCHMARK(Random1MB);

static void Random100MB(benchmark::State& state) {
    static constexpr std::string filename = "Random100M.bin";
    static constexpr size_t size = (static_cast<size_t>(1) << 20) * 100;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        std::ofstream file(TestFilesFolder + filename, std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder + filename + ".");
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i) {
            rng(buffer, BUFFER_SIZE);
            file.write(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
            if (!file) throw std::runtime_error("Запись прервана после записи " + std::to_string(i * BUFFER_SIZE) + " байт.");
        }
        if constexpr (remainder > 0) {
            rng(buffer, remainder);
            file.write(reinterpret_cast<char *>(buffer), static_cast<std::streamsize>(remainder));
            if (!file)
                throw std::runtime_error("Запись прервана после записи "  + std::to_string(num_of_blocks * BUFFER_SIZE) + " байт.");
        }
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
    remove(filename.c_str());
}
BENCHMARK(Random100MB);

static void Random1000MB(benchmark::State& state) {
    static constexpr std::string filename = "Random1000M.bin";
    static constexpr size_t size = (static_cast<size_t>(1) << 20) * 1000;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        std::ofstream file(TestFilesFolder + filename, std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть " TestFilesFolder + filename + ".");
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i) {
            rng(buffer, BUFFER_SIZE);
            file.write(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
            if (!file) throw std::runtime_error("Запись прервана после записи " + std::to_string(i * BUFFER_SIZE) + " байт.");
        }
        if constexpr (remainder > 0) {
            rng(buffer, remainder);
            file.write(reinterpret_cast<char *>(buffer), static_cast<std::streamsize>(remainder));
            if (!file)
                throw std::runtime_error("Запись прервана после записи "  + std::to_string(num_of_blocks * BUFFER_SIZE) + " байт.");
        }
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
    remove(filename.c_str());
}
BENCHMARK(Random1000MB);

static void Random1MB_NoFile(benchmark::State& state) {
    static constexpr size_t size = static_cast<size_t>(1) << 20;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i)
            rng(buffer, BUFFER_SIZE);
        if constexpr (remainder > 0)
            rng(buffer, remainder);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
}
BENCHMARK(Random1MB_NoFile);

static void Random100MB_NoFile(benchmark::State& state) {
    static constexpr size_t size = (static_cast<size_t>(1) << 20) * 100;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i)
            rng(buffer, BUFFER_SIZE);
        if constexpr (remainder > 0)
            rng(buffer, remainder);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
}
BENCHMARK(Random100MB_NoFile);

static void Random1000MB_NoFile(benchmark::State& state) {
    static constexpr size_t size = (static_cast<size_t>(1) << 20) * 1000;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i)
            rng(buffer, BUFFER_SIZE);
        if constexpr (remainder > 0)
            rng(buffer, remainder);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
}
BENCHMARK(Random1000MB_NoFile);

static void Gen1000Keys(benchmark::State& state) {
    static constexpr size_t size = 1000 * KEY_SIZE;
    static constexpr size_t num_of_blocks = size / BUFFER_SIZE;
    static constexpr size_t remainder = size % BUFFER_SIZE;
    uint8_t buffer[BUFFER_SIZE];

    for (auto _ : state) {
        CTR_DRBG<Kuznechik, true> rng;
        for (size_t i = 0; i < num_of_blocks; ++i)
            rng(buffer, BUFFER_SIZE);
        if constexpr (remainder > 0)
            rng(buffer, remainder);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(size));
}
BENCHMARK(Gen1000Keys);

BENCHMARK_MAIN();