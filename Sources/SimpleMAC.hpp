/*  Одна из возможных конструкций выработки промежуточного ключа
    в Р 1323565.1.022—2018. Её применение возможного только если
    мастер-ключ надлежащего качества.
*/
#ifndef SIMPLE_MAC_HPP
#define SIMPLE_MAC_HPP

#include "Hash.hpp"

template <size_t Size>
class SimpleMAC : public MAC<Size, Size, Size> {
private:
    SecureBuffer<Size> key_;
    SecureBuffer<Size> result_;
    SecureBuffer<Size> buffer_;
    size_t buffered_length_;

    inline void finalize() { memset(buffer_.raw() + buffered_length_, 0, Size - buffered_length_); result_ += buffer_; }
public:
    SimpleMAC() : buffered_length_(0) {}
    inline void initKeySchedule(const SecureBuffer<Size> &key) noexcept override { key_ = key; result_ = key; }
    inline SimpleMAC(const SecureBuffer<Size> &key) noexcept : SimpleMAC() { initKeySchedule(key); }
    void update(const uint8_t *data, const size_t size) noexcept override;
    inline void update(const std::vector<uint8_t> &data) noexcept override
        { update(data.data(), data.size()); }
    inline std::vector<uint8_t> digest() noexcept override
        { finalize(); return std::vector<uint8_t>(result_.begin(), result_.end()); }
    inline void digest(uint8_t *digest_buffer) noexcept override
        { finalize(); memcpy(digest_buffer, result_.raw(), Size); }
    inline void clear() noexcept override
        { result_ = key_; buffered_length_ = 0; }

    static constexpr size_t BlockSize = Size;
    static constexpr size_t DigestSize = Size;
    static constexpr size_t KeySize = Size;
};

template <size_t Size>
void SimpleMAC<Size>::update(const uint8_t *data, const size_t size) noexcept {
    size_t current_index = 0;
    while (size - current_index > 0) {
        if (buffered_length_ == Size) {
            buffered_length_ = 0;
            result_ += buffer_;
        }
        uint8_t to_copy = static_cast<uint8_t>(
            std::min(static_cast<size_t>(Size - buffered_length_), size - current_index)
        );
        std::copy(
            data + static_cast<ptrdiff_t>(current_index),
            data + static_cast<ptrdiff_t>(current_index + to_copy),
            buffer_.begin() + buffered_length_
        );
        buffered_length_ += to_copy;
        current_index += to_copy;
    }
}

#endif