#ifndef CRISP_MESSAGE_HPP
#define CRISP_MESSAGE_HPP

#include <vector>
#include "CryptographicSuites.hpp"

class CRISPMessage {
public:
    struct KeyID {
        uint8_t small_value;
        std::vector<uint8_t> big_value;
        uint8_t size;
        inline bool operator==(const KeyID&) const = default;
    };
    inline CRISPMessage(
        const bool external_key_id_flag,
        const uint16_t verison,
        const CryptographicSuites::ID cryptographic_suite,
        const KeyID key_id,
        const uint64_t seq_num,
        const std::vector<uint8_t> payload,
        const std::vector<uint8_t> ICV
    ) noexcept :
        external_key_id_flag_(external_key_id_flag),
        version_(verison),
        cryptographic_suite_(cryptographic_suite),
        key_id_(key_id),
        seq_num_(seq_num),
        payload_(payload),
        ICV_(ICV) {}
    CRISPMessage(const std::vector<uint8_t> &message);
    std::vector<uint8_t> serialize() const noexcept;
    inline bool externalKeyIDFlag() const noexcept
        { return external_key_id_flag_; }
    inline uint16_t version() const noexcept
        { return version_; }
    inline CryptographicSuites::ID cryptographicSuite() const noexcept
        { return cryptographic_suite_; }
    inline const KeyID &keyID() const noexcept
        { return key_id_; }
    inline uint64_t seqNum() const noexcept
        { return seq_num_; }
    inline const std::vector<uint8_t> &payload() const noexcept
        { return payload_; }
    inline const std::vector<uint8_t> &ICV() const noexcept
        { return ICV_; }
    inline bool operator==(const CRISPMessage&) const noexcept = default;
    inline bool operator<(const CRISPMessage &other) const noexcept { return seq_num_ < other.seq_num_; }

    static size_t precalcSizeWithoutPayload(
        const size_t key_id_size,
        const CryptographicSuites::ID cryptographic_suite
    ) noexcept;
    inline static size_t precalcSize(
        const size_t payload_size,
        const size_t key_id_size,
        const CryptographicSuites::ID cryptographic_suite
    ) noexcept { return precalcSizeWithoutPayload(key_id_size, cryptographic_suite) + payload_size; }
    static constexpr size_t MaxSize = 2048;
private:
    bool external_key_id_flag_;
    uint16_t version_;
    CryptographicSuites::ID cryptographic_suite_;
    KeyID key_id_;
    uint64_t seq_num_;
    std::vector<uint8_t> payload_;
    std::vector<uint8_t> ICV_;
};

#endif