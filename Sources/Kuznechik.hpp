#ifndef KUZNECHIK_HPP
#define KUZNECHIK_HPP

#include "Cipher.hpp"

class Kuznechik final : public Cipher<16, 32> {
private:
    SecureBuffer<16> key_schedule_[10];
public:
    static constexpr size_t BlockSize = 16;
    static constexpr size_t KeySize = 32;

    Kuznechik() noexcept = default;
    void initKeySchedule(const SecureBuffer<32> &key) noexcept override;
    inline Kuznechik(const SecureBuffer<32> &key) noexcept
        { initKeySchedule(key); }
    SecureBuffer<16> &encrypt(SecureBuffer<16> &plain_text) const noexcept override;
    SecureBuffer<16> &decrypt(SecureBuffer<16> &encrypted_text) const noexcept override;
    inline ~Kuznechik() { LOG(INFO) << "Раундовые ключи Кузнечика очищены из памяти"; }
    #ifdef UNIT_TESTS
        const SecureBuffer<16> *getKeySchedule() const noexcept;
    #endif
};

#ifdef UNIT_TESTS
    SecureBuffer<16> &testSubstitute(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testInverseSubstitute(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testLinear(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testInverseLinear(SecureBuffer<16> &vector) noexcept;
#endif

#endif