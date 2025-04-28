#ifndef KUZNECHIK_HPP
#define KUZNECHIK_HPP

#include "Cipher.hpp"

class Kuznechik final : public Cipher<16> {
private:
    SecureBuffer<16> key_schedule_[10];
public:
    Kuznechik() = default;
    void initKeySchedule(const SecureBuffer<32> &key) noexcept;
    Kuznechik(const SecureBuffer<32> &key);
    SecureBuffer<16> &encrypt(SecureBuffer<16> &plain_text) const noexcept override;
    SecureBuffer<16> &decrypt(SecureBuffer<16> &encrypted_text) const noexcept override;
    #ifdef UNIT_TESTS
        const SecureBuffer<16> *getKeySchedule() const noexcept;
    #endif
};

#ifdef UNIT_TESTS
    SecureBuffer<16> &testSubstitute(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testInverseSubstitute(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testR(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testInvR(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testL(SecureBuffer<16> &vector) noexcept;
    SecureBuffer<16> &testInvL(SecureBuffer<16> &vector) noexcept;
#endif

#endif