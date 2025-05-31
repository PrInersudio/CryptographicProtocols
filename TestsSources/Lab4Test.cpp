#include <benchmark/benchmark.h>
#ifndef UNIT_TESTS
#define UNIT_TESTS
#endif
#include "CRISPMessenger.hpp"

INITIALIZE_EASYLOGGINGPP

struct LogConfer {
    LogConfer() { confLog(); }
};

LogConfer confer;

#define MESSAGESS_NUM 1000

static const SecureBuffer key = {
        'T', 'E', 'S', 'T', 'T', 'E', 'S', 'T',
        'T', 'E', 'S', 'T', 'T', 'E', 'S', 'T',
        'T', 'E', 'S', 'T', 'T', 'E', 'S', 'T',
        'T', 'E', 'S', 'T', 'T', 'E', 'S', 'T'
    };
    static constexpr uint8_t user1[] = {'A', 'l', 'i', 'c', 'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static constexpr uint8_t user2[] = {'B', 'o', 'b', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void recvThread(const CryptographicSuites::ID suite) {
    CRISPMessenger messenger2(
        11012, "127.0.0.1", 11011,
        suite, key, user2, user1
    );
    for (uint16_t i = 0; i < MESSAGESS_NUM; ++i)
        messenger2.recv();
}

void sendThread(const CryptographicSuites::ID suite) {
    CRISPMessenger messenger1(
        11011, "127.0.0.1", 11012,
        suite, key, user1, user2
    );
    for (uint16_t i = 0; i < MESSAGESS_NUM; ++i)
        messenger1.send("datadatadatadat", false);
}

static void NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC(benchmark::State& state) {
    for (auto _ : state) {
        std::thread sendT(sendThread, CryptographicSuites::ID::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC);
        recvThread(CryptographicSuites::ID::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC);
        sendT.join();
    }
    state.SetBytesProcessed(state.iterations() * 16);
}
BENCHMARK(NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC);

BENCHMARK_MAIN();