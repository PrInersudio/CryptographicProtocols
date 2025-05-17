#ifndef STREEBOG_HPP
#define STREEBOG_HPP

#include "SecureBuffer.hpp"
#include "Hash.hpp"

class Streebog {
public:
    enum class EndianOfUInt512 { Big = false, Little = true };

    Streebog(const Streebog &) = delete;
    Streebog(Streebog &&) = default;
    Streebog& operator=(const Streebog &) = delete;
    Streebog& operator=(Streebog&&) noexcept = default;
    void update(const uint8_t *data, const size_t size) noexcept;
    inline void update(const std::vector<uint8_t> &data) noexcept
        { update(data.data(), data.size()); }
    // Реализовано два варианта возврата хэша.
    // В Big Endian как в стандарте.
    // В Little Endian как OpenSSL Gost Engine.
    std::vector<uint8_t> digest(const EndianOfUInt512 endian) noexcept;
    void digest(uint8_t *digest_buffer, const EndianOfUInt512 endian) noexcept;
    inline void clear() noexcept
        {buffered_length_ = 0; initHash(); N_.zero(); Sum_.zero();}
    
#ifdef UNIT_TESTS
    SecureBuffer<64> &getBuffer() noexcept;
    uint8_t getBufferedLength() noexcept;
    SecureBuffer<64> &getHash() noexcept;
    SecureBuffer<64> &getN() noexcept;
    SecureBuffer<64> &getSum() noexcept;
    void testAddToN(const uint16_t addition) noexcept;
    void testAddToSum() noexcept;
    void testCompress(const SecureBuffer<64> &N, const SecureBuffer<64> &m) noexcept;
#endif

protected:
    enum class Variant { Streebog256 = 256, Streebog512 = 512 };
    Streebog(const Variant variant) noexcept;
    inline Variant variant() const noexcept { return variant_;}
private:
    SecureBuffer<64> buffer_;
    uint8_t buffered_length_;
    SecureBuffer<64> hash_;
    SecureBuffer<64> N_;
    SecureBuffer<64> Sum_;
    const Variant variant_;
    
    void initHash();
    void addToN(const uint16_t addition) noexcept;
    void addToSum() noexcept;
    void compress(const SecureBuffer<64> &N, const SecureBuffer<64> &m) noexcept;
    void finalize() noexcept;
};

class Streebog256 : public Hash<64, 32>, public Streebog {
public:
    Streebog256() : Streebog(Variant::Streebog256) {}
    inline void update(const uint8_t *data, const size_t size) override
        { Streebog::update(data, size); }
    inline void update(const std::vector<uint8_t> &data) override
        { Streebog::update(data);}
    inline std::vector<uint8_t> digest(const EndianOfUInt512 endian)
        { return Streebog::digest(endian); }
    inline std::vector<uint8_t> digest() override
        { return digest(EndianOfUInt512::Little);}
    inline void digest(uint8_t *digest_buffer, const EndianOfUInt512 endian) noexcept
        { Streebog::digest(digest_buffer, endian); }
    inline void digest(uint8_t *digest_buffer) noexcept override
        { digest(digest_buffer, EndianOfUInt512::Little); }
    inline void clear() override
        { Streebog::clear(); }
};

class Streebog512 : public Hash<64, 64>, public Streebog {
public:
    Streebog512() noexcept : Streebog(Variant::Streebog512) {}
    inline void update(const uint8_t *data, const size_t size) override
        { Streebog::update(data, size); }
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { Streebog::update(data);}
    inline std::vector<uint8_t> digest(const EndianOfUInt512 endian) noexcept
        { return Streebog::digest(endian); }
    inline std::vector<uint8_t> digest() noexcept override
        { return digest(EndianOfUInt512::Little);}
    inline void digest(uint8_t *digest_buffer, const EndianOfUInt512 endian) noexcept
        { Streebog::digest(digest_buffer, endian); }
    inline void digest(uint8_t *digest_buffer) noexcept override
        { digest(digest_buffer, EndianOfUInt512::Little); }
    inline void clear() noexcept override
        { Streebog::clear(); }
};

#ifdef UNIT_TESTS
SecureBuffer<64> &testLPS(SecureBuffer<64> &vector) noexcept;
#endif

#endif