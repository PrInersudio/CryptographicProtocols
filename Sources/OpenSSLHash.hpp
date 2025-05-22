#ifndef OPENSSL_HASH_HPP
#define OPENSSL_HASH_HPP

#include <stdexcept>
#include <openssl/evp.h>
#include "Hash.hpp"

template <size_t BlockLen, size_t DigestLen>
class OpenSSLHash : public Hash<BlockLen, DigestLen> {
private:
    EVP_MD_CTX *ctx_;

    static bool OpenSSLAddedAllAlgs;
public:
    OpenSSLHash(const char *algname);
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { EVP_DigestUpdate(ctx_, data.data(), data.size()); }
    inline void update(const uint8_t *data, const size_t size) noexcept override
        { EVP_DigestUpdate(ctx_, data, size); }
    inline std::vector<uint8_t> digest() noexcept override
        { std::vector<uint8_t> result(DigestLen); EVP_DigestFinal_ex(ctx_, result.data(), NULL); return result; }
    inline void digest(uint8_t *digest_buffer)
        { EVP_DigestFinal_ex(ctx_, digest_buffer, NULL); }
    inline void clear() noexcept override
        { EVP_DigestInit_ex(ctx_, nullptr, nullptr); }
    ~OpenSSLHash() noexcept;

    static constexpr size_t BlockSize = BlockLen;
    static constexpr size_t DigestSize = DigestLen;
};

template <size_t BlockLen, size_t DigestLen>
bool OpenSSLHash<BlockLen, DigestLen>::OpenSSLAddedAllAlgs = false;

template <size_t BlockLen, size_t DigestLen>
OpenSSLHash<BlockLen, DigestLen>::OpenSSLHash(const char *algname) {
    if (!OpenSSLAddedAllAlgs) {
        OPENSSL_add_all_algorithms_conf();
        OpenSSLAddedAllAlgs = true;
    }
    const EVP_MD *md = EVP_get_digestbyname(algname);
    if (md == nullptr) throw std::runtime_error("Не найден алгоритм " + std::string(algname) + ".");
    ctx_ = EVP_MD_CTX_new();
    if (ctx_ == nullptr) throw std::bad_alloc();
    EVP_DigestInit_ex(ctx_, md, NULL);
}

template <size_t BlockLen, size_t DigestLen>
OpenSSLHash<BlockLen, DigestLen>::~OpenSSLHash() noexcept {
    EVP_MD_CTX_free(ctx_);
}

#endif