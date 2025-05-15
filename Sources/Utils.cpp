#include <fstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include "Utils.hpp"

void checkTimestamp(const uint64_t timestamp_raw) noexcept {
    const auto timestamp =
        std::chrono::system_clock::time_point(std::chrono::seconds(timestamp_raw));
    const auto now = std::chrono::system_clock::now();
    std::cout
        << "Время создания ключа: "
        << std::format("{:%Y-%m-%d %H:%M:%S}", timestamp)
    << std::endl;
    std::cout
        << "Текущее время: "
        << std::format("{:%Y-%m-%d %H:%M:%S}", now)
    << std::endl;
    const auto diff = now - timestamp;
    if (diff > std::chrono::years(1) + std::chrono::months(6))
        std::cout <<
            "Внимание! "
            "Срок действия ключа подошёл к концу! "
            "Безопасность зашифрованной информации не гарантируется."
            << std::endl;
    else if (diff > std::chrono::years(1))
        std::cout <<
            "Внимание! "
            "Срок действия ключа подходит к концу! "
            "Запланируйте его замену в ближайшее время."
            << std::endl;
    else
        std::cout <<
            "Проверка срока действия ключа прошла успешно. "
            "Дополнительных действий не требуется."
            << std::endl;
}

void initKuznechikCTX(Kuznechik &ctx, const char *filename) {
    uint64_t timestamp;
    SecureBuffer<32> key;
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Не удалось открыть файл ключа.");
    file.read(reinterpret_cast<char *>(&timestamp), 8);
    if (!file) throw std::runtime_error("Ошибка чтения временной метки из файла ключа.");
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    timestamp = __builtin_bswap64(timestamp);
    #endif
    file.read(reinterpret_cast<char *>(key.raw()), 32);
    if (!file) throw std::runtime_error("Ошибка чтения ключа из файла.");
    checkTimestamp(timestamp);
    ctx.initKeySchedule(key);
}

std::vector<uint8_t> parseHexString(const std::string& hex) {
    if (hex.length() % 2 != 0)
        throw std::invalid_argument("Hex-строка должна иметь чётную длину.");
    std::vector<uint8_t> result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string toHexString(const std::vector<uint8_t> &data) noexcept {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto &byte : data)
        oss << std::setw(2) << static_cast<int>(byte);
    return oss.str();
}

bool fillBuffer(std::ifstream &file, std::vector<uint8_t> &buffer) noexcept {
    buffer.resize(BUFFER_SIZE);
    file.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE);
    buffer.resize(static_cast<std::vector<uint8_t>::size_type>(file.gcount()));
    return !file.eof();
}