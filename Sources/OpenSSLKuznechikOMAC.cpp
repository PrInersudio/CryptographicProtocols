#include "OpenSSLKuznechikOMAC.hpp"

void OpenSSLKuznechikOMAC::initKeySchedule(const SecureBuffer<32> &key) {
    key_ = key;
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
    if (!EVP_MAC_init(ctx_, key_.raw(), 32, params)) {
        EVP_MAC_CTX_free(ctx_);
        EVP_MAC_free(mac_);
        throw std::runtime_error("Ошибка инициализации CMAC.");
    }
}

void OpenSSLKuznechikOMAC::update(const uint8_t *data, const size_t size) {
    if (!EVP_MAC_update(ctx_, data, size))
        throw std::runtime_error("Ошибка обновления CMAC.");
}

std::vector<uint8_t> OpenSSLKuznechikOMAC::digest(const size_t size) {
    if (size > 16)
        throw std::out_of_range("Запрошенный размер MAC превышает допустимый.");
    std::vector<uint8_t> out(16);
    if (!EVP_MAC_final(ctx_, out.data(), NULL, 16))
        throw std::runtime_error("Ошибка получения финального значения CMAC.");
    out.resize(size);
    return out;
}

void OpenSSLKuznechikOMAC::digest(uint8_t *digest_buffer) {
    if (!EVP_MAC_final(ctx_, digest_buffer, NULL, 16))
        throw std::runtime_error("Ошибка получения финального значения CMAC.");
}