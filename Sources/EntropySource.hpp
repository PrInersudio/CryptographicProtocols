#ifndef ENTROPYSOURCE_HPP
#define ENTROPYSOURCE_HPP

#include <fstream>
#include "SecureBuffer.hpp"

template <size_t SeedLen>
class EntropySource {
public:
    virtual SecureBuffer<SeedLen> operator()() const = 0;
    virtual ~EntropySource() = default;
};

template <size_t SeedLen>
class Urandom : public EntropySource<SeedLen> {
public:
    SecureBuffer<SeedLen> operator()() const override {
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (!urandom)
            throw std::runtime_error("Не удалось получить доступ к /dev/urandom.");
        SecureBuffer<SeedLen> entropy;
        urandom.read(reinterpret_cast<char *>(entropy.raw()), SeedLen);
        if (!urandom)
            throw std::runtime_error("Не удалось получить энтропию из /dev/urandom.");
        LOG(INFO) << "Обращение к urandom.";
        return entropy;
    }
};

template <typename T, size_t SeedLen>
concept IsEntropySource = requires {
    { T() };
    requires std::is_base_of_v<EntropySource<SeedLen>, T>;
};

#endif