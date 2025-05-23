#include "CRISPMessage.hpp"

using diff_type = std::vector<uint8_t>::difference_type;

CRISPMessage::CRISPMessage(const std::vector<uint8_t> &message) {
    external_key_id_flag_ = message[0] & 0x80 ? true : false;
    verison_ = (static_cast<uint16_t>(0x7F & message[0]) << 8) | message[1];
    cryptographic_suite_ = static_cast<CryptographicSuites>(message[2]);
    if (!(message[3] & 0x80)) {
        key_id_.size = 1;
        key_id_.small_value = message[3];
    }
    else {
        key_id_.small_value = 0;
        key_id_.size = message[3] & 0x7F;
        key_id_.big_value = std::vector(
            message.begin() + 4, message.begin() + 4 + key_id_.size
        );
    }
    const diff_type offset =
        key_id_.size == 0 ? 4 : 3 + key_id_.size;
    seq_num_ = 0;
    for (diff_type i = offset; i < offset + 6; ++i)
        seq_num_ = (seq_num_ << 8) | message[static_cast<size_t>(i)];
    const size_t ICV_length = getICVLength(cryptographic_suite_);
    payload_ = std::vector(message.begin() + offset + 6,
        message.end() - static_cast<diff_type>(ICV_length));
    ICV_ = std::vector(message.end() - static_cast<diff_type>(ICV_length),
        message.end());
}

std::vector<uint8_t> CRISPMessage::serialize() const noexcept {
    std::vector<uint8_t> message(
        2 + 1 + 1 + (key_id_.size == 1 ? 0 : key_id_.size) +
        6 + payload_.size() + ICV_.size()
    );
    message[0] = static_cast<uint8_t>(verison_ >> 8);
    message[1] = static_cast<uint8_t>(verison_ & 0xFF);
    if (external_key_id_flag_) message[0] |= 0x80;
    message[2] = static_cast<uint8_t>(cryptographic_suite_);
    if (key_id_.size == 1)
        message[3] = key_id_.small_value;
    else {
        message[3] = key_id_.size | 0x80;
        std::copy(key_id_.big_value.begin(), key_id_.big_value.end(), message.begin() + 4);
    }
    const diff_type offset =
        key_id_.size == 0 ? 4 : 3 + key_id_.size;
    for (diff_type i = 0; i < 6; ++i)
        message[static_cast<size_t>(offset + i)] =
            static_cast<uint8_t>((seq_num_ >> (8 * (5 - i))) & 0xFF);
    std::copy(payload_.begin(), payload_.end(), message.begin() + offset + 6);
    std::copy(ICV_.begin(), ICV_.end(),
        message.end() - static_cast<diff_type>(ICV_.size()));
    return message;
}