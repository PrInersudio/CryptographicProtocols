#ifndef CRISP_MESSENGER_HPP
#define CRISP_MESSENGER_HPP

#include <filesystem>
#include "TCP.hpp"
#include "CTR_DRBG.hpp"
#include "CRISPMessage.hpp"
#include "KDF_R_13235651022.hpp"
#include "NMAC256.hpp"
#include "HMAC.hpp"
#include "SimpleMAC.hpp"
#include "Utils.hpp"

class CRISPMessenger {
private:
    static constexpr uint8_t rng_personalization_string[] =
        { 'C', 'R', 'I', 'S', 'P', 'M', 'e', 's', 's', 'a', 'n', 'g', 'e', 'r'};
    static constexpr uint8_t kdf_mac_application_info[] = {
            'C', 'R', 'I', 'S', 'P', 'M', 'e', 's',
            's', 'a', 'n', 'g', 'e', 'r', ' ', 'k',
            'e', 'y', ' ', 'f', 'o', 'r', ' ', 'M',
            'A', 'C', ' ', 'd', 'i', 'g', 'e', 's',
    };
    static constexpr uint8_t kdf_key_application_info[] = {
            'C', 'R', 'I', 'S', 'P', 'M', 'e', 's',
            's', 'a', 'n', 'g', 'e', 'r', ' ', 'k',
            'e', 'y', ' ', 'f', 'o', 'r', ' ', 'e',
            'n', 'c', 'r', 'y', 'p', 't', 'i', 'o ',
    };
    static constexpr uint8_t kdf_additional_info[16] = {};

    template <size_t EncryptionKeySize, size_t MacKeySize>
    struct KeyPair {
        SecureBuffer<EncryptionKeySize> encryption_key;
        SecureBuffer<MacKeySize> mac_key;
    };

    struct MessageParts {
        uint64_t seq_num;
        std::vector<uint8_t> part;
        inline bool operator<(const MessageParts &other) const noexcept { return seq_num < other.seq_num; }
        inline uint8_t &operator[](size_t i) noexcept { return part[i]; }
        inline const uint8_t &operator[](size_t i) const noexcept { return part[i]; }
    };

    using MessageFormer = std::function<CRISPMessage(const MessageParts &)>;

    TCPServer server_;
    TCPClient client_;
    const CryptographicSuites server_cryptographic_suite_;
    MessageFormer formMessage;
    CTR_DRBG<Kuznechik, true> rng;
    uint64_t client_seq_num_;
    SecureBuffer<32> master_key_;
    uint8_t local_user_info_[16];
    uint8_t remote_user_info_[16];
    const std::filesystem::path directory_;
    const size_t max_payload_size_;

    template <IsMAC InnerMAC, IsMAC OuterMAC>
    requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
    void getKuznechikCMAC_256_128_R13235651022MacKey(SecureBuffer<32> &mac_key, const SecureBuffer<32> &salt, const uint8_t (&user_info)[16]) const noexcept;

    template <IsMAC InnerMAC, IsMAC OuterMAC>
    requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
    void getKuznechikCTR_KuznechikCMAC_256_128_R13235651022Keys(KeyPair<32, 32> &keys, const SecureBuffer<32> &salt, const uint8_t (&user_info)[16]) const noexcept;

    bool checkMAC_KuznechikCMAC_256_128_R13235651022(const CRISPMessage &message, const SecureBuffer<32> &mac_key) const noexcept;
    static std::vector<uint8_t> encryptKuznechikCTR(const uint64_t seq_num, const std::vector<uint8_t> &data, const SecureBuffer<32> &key) noexcept;
    inline static std::vector<uint8_t> decryptKuznechikCTR(const uint64_t seq_num, const std::vector<uint8_t> &data, const SecureBuffer<32> &key, const uint8_t (&user_info)[16]) noexcept
        { encryptKuznechikCTR(seq_num, data, key); }
    
    template <IsMAC InnerMAC, IsMAC OuterMAC>
    requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
    inline std::vector<uint8_t> handleNULL_KuznechikCMAC_256_128_R13235651022(const CRISPMessage &message, const uint8_t (&user_info)[16]) const {
        SecureBuffer<32> salt;
        std::copy(message.ICV().begin(), message.ICV().begin() + 32, salt.begin());
        SecureBuffer<32> mac_key;
        getKuznechikCMAC_256_128_R13235651022MacKey(mac_key, salt, user_info);
        if(!checkMAC_KuznechikCMAC_256_128_R13235651022(message, mac_key))
            throw std::runtime_error("Нарушена целостность сообщения.");
        return message.payload();
    }

    template <IsMAC InnerMAC, IsMAC OuterMAC>
    requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
    inline std::vector<uint8_t> handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022(const CRISPMessage &message, const uint8_t (&user_info)[16]) const {
        SecureBuffer<32> salt;
        std::copy(message.ICV().begin(), message.ICV().begin() + 32, salt.begin());
        KeyPair<32, 32> keys;
        getKuznechikCTR_KuznechikCMAC_256_128_R13235651022Keys(keys, salt, user_info);
        if(!checkMAC_KuznechikCMAC_256_128_R13235651022(message, keys.mac_key))
            throw std::runtime_error("Нарушена целостность сообщения.");
        return decryptKuznechikCTR(message.seq_num(), message.payload(), keys.encryption_key);
    }

    template <IsMAC InnerMAC, IsMAC OuterMAC>
    requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
    CRISPMessage formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage(const MessageParts &message) const;

    template <IsMAC InnerMAC, IsMAC OuterMAC>
    requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
    CRISPMessage formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage(const MessageParts &message) const;

    MessageFormer chooseMessageFormer();
    
    MessageParts getMessage(const TCP &tcp) const;
    inline void sendMessage(const TCP &tcp, const MessageParts &message) const {
        std::vector<uint8_t> crisp_message_bytes = formMessage(message).serialize();
        std::vector<uint8_t> size_bytes(2);
        size_bytes[0] = static_cast<uint8_t>((message.part.size() >> 8) & 0xFF);
        size_bytes[1] = static_cast<uint8_t>(message.part.size() & 0xFF);
        tcp(size_bytes);
        tcp(crisp_message_bytes);
    }
public:
    CRISPMessenger(
        const uint16_t local_port,
        const std::string &remote_ip,
        const uint16_t remote_port,
        const CryptographicSuites server_cryptographic_suite,
        const char *key_file,
        const uint8_t (&local_user_info)[16],
        const uint8_t (&remote_user_info)[16],
        const char *file_directory
    );
    std::string recv();
    void send(std::string msg, bool is_file);
};

template <IsMAC InnerMAC, IsMAC OuterMAC>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
void CRISPMessenger::getKuznechikCMAC_256_128_R13235651022MacKey(SecureBuffer<32> &mac_key, const SecureBuffer<32> &salt, const uint8_t (&user_info)[16]) const noexcept {
    KDF_R_13235651022<InnerMAC, OuterMAC, 32> kdf(master_key_, salt);
    uint8_t IV[OuterMAC::DigestSize];
    uint64_t temp = message.seqNum();
    for (uint8_t i = 0; i < OuterMAC::DigestSize; ++i) {
        IV[OuterMAC::DigestSize - 1 - i] = static_cast<uint8_t>(temp);
        temp >>= 8;
    }
    kdf.fetch(mac_key.raw(), 32, IV, kdf_mac_application_info, user_info, kdf_additional_info);
}

template <IsMAC InnerMAC, IsMAC OuterMAC>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
void CRISPMessenger::getKuznechikCTR_KuznechikCMAC_256_128_R13235651022Keys(KeyPair<32, 32> &keys, const SecureBuffer<32> &salt, const uint8_t (&user_info)[16]) const noexcept {
    KDF_R_13235651022<InnerMAC, OuterMAC, 32> kdf(master_key_, salt);
    uint8_t IV[OuterMAC::DigestSize];
    uint64_t temp = message.seqNum();
    for (uint8_t i = 0; i < OuterMAC::DigestSize; ++i) {
        IV[OuterMAC::DigestSize - 1 - i] = static_cast<uint8_t>(temp);
        temp >>= 8;
    }
    kdf.fetch(keys.mac_key.raw(), 32, IV, kdf_mac_application_info, user_info, kdf_additional_info);
    kdf.fetch(keys.encryption_key.raw(), 32, IV, kdf_key_application_info, user_info, kdf_additional_info);
}

inline bool checkMAC_KuznechikCMAC_256_128_R13235651022(const CRISPMessage &message, const SecureBuffer<32> &mac_key) {
    uint8_t mac[16];
    memcpy(mac, message.ICV().data() + 32, 16);
    OMAC<Kuznechik> macer(mac_key);
    macer.update(message.payload());
    uint8_t calculated_mac[16];
    macer.digest(calculated_mac);
    return !memcmp(mac, calculated_mac, 16);
}

inline static std::string bytesToString(const uint8_t *bytes, const size_t size) noexcept {
    return std::string(reinterpret_cast<const char *>(bytes), size);
}

inline static std::string sanitizeFilename(const std::string& raw) {
    std::string name =  std::filesystem::path(raw).filename().string();
    if (name.empty() || name == "." || name == "..")
        throw std::runtime_error("Обнаружена попытка path traversal.");
    return name;
}

template <IsMAC InnerMAC, IsMAC OuterMAC>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
CRISPMessage CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage(const MessageParts &message) const {
    static constexpr uint8_t rng_additional_info[] = {
        'C', 'R', 'I', 'S', 'P', 'M', 'e', 's',
        's', 'a', 'n', 'g', 'e', 'r', ':', ':',
        'f', 'o', 'r', 'm', 'N', 'U', 'L', 'L',
        '_', 'K', 'u', 'z', 'n', 'e', 'c', 'h',
        'i', 'k', 'C', 'M', 'A', 'C', '_', '2',
        '5', '6', '_', '1', '2', '8', '_', 'R',
        '1', '3', '2', '3', '5', '6', '5', '1',
        '0', '2', '2', 'C', 'R', 'I', 'S', 'P',
        'M', 'e', 's', 's', 'a', 'g', 'e'
    },

    SecureBuffer<32> salt; 
    rng(salt.raw(), 32, rng_additional_info. sizeof(rng_additional_info));
    SecureBuffer<32> mac_key;
    getKuznechikCMAC_256_128_R13235651022MacKey<InnerMAC, OuterMAC>(mac_key, salt, local_user_info_);
    OMAC<Kuznechik> macer(mac_key);
    macer.update(message.part);

    std::vector<uint8_t> ICV(48);
    std::copy(salt.begin(), salt.end(), ICV.begin());
    macer.digest(ICV + 32);

    return CRISPMessage(false, 0, server_cryptographic_suite_, {0, {}, 0}, message.seq_num, message.part, ICV);
}

template <IsMAC InnerMAC, IsMAC OuterMAC>
requires (InnerMAC::DigestSize >= OuterMAC::KeySize)
CRISPMessage CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage(const MessageParts &message) const {
    static constexpr uint8_t rng_additional_info[] = {
        'f', 'o', 'r', 'm', 'K', 'u', 'z', 'n',
        'e', 'c', 'h', 'i', 'k', 'C', 'T', 'R',
        '_', 'K', 'u', 'z', 'n', 'e', 'c', 'h',
        'i', 'k', 'C', 'M', 'A', 'C', '_', '2',
        '5', '6', '_', '1', '2', '8', '_', 'R',
        '1', '3', '2', '3', '5', '6', '5', '1',
        '0', '2', '2', 'C', 'R', 'I', 'S', 'P',
        'M', 'e', 's', 's', 'a', 'g', 'e'
    },

    SecureBuffer<32> salt; 
    rng(salt.raw(), 32, rng_additional_info. sizeof(rng_additional_info));
    KeyPair<32, 32> keys;
    getKuznechikCTR_KuznechikCMAC_256_128_R13235651022Keys<InnerMAC, OuterMAC>(keys, salt, local_user_info_);

    std::vector<uint8_t> payload = encryptKuznechikCTR(message.seq_num, message.part, keys.encryption_key);
    OMAC<Kuznechik> macer(keys.mac_key);
    macer.update(message.part);

    std::vector<uint8_t> ICV(48);
    std::copy(salt.begin(), salt.end(), ICV.begin());
    macer.digest(ICV + 32);

    return CRISPMessage(false, 0, server_cryptographic_suite_, {0, {}, 0}, message.seq_num, payload, ICV);
}

#endif