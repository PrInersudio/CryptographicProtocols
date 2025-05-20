#ifndef SECURE_BUFFER_HPP
#define SECURE_BUFFER_HPP

#include <cinttypes>
#include <string.h>
#include <sys/mman.h>
#include <algorithm>
#include <functional>
#include <random>

template <size_t N>
class SecureBuffer {
private:
    uint8_t data_[N];
public:
    SecureBuffer();
    SecureBuffer(std::initializer_list<uint8_t> init);
    SecureBuffer(const SecureBuffer &original) noexcept;
    SecureBuffer(SecureBuffer &&other);
    inline SecureBuffer& operator=(const SecureBuffer &original) noexcept
        { if (this != &original) std::copy(original.data_, original.data_ + N, data_); return *this; }
    inline SecureBuffer& operator=(SecureBuffer &&original) noexcept
        { if (this != &original) {std::copy(original.data_, original.data_ + N, data_); original.zero();} return *this; }
    ~SecureBuffer() noexcept;
    inline uint8_t &operator[](const size_t i) noexcept { return data_[i]; }
    inline const uint8_t &operator[](const size_t i) const noexcept { return data_[i]; }
    inline bool operator==(const SecureBuffer &other) const noexcept { return !memcmp(data_, other.data_, N); }
    inline uint8_t *raw() noexcept { return data_; }
    inline const uint8_t *raw() const noexcept { return data_; }
    inline void zero() noexcept { memset(data_, 0, N); }
    SecureBuffer<N> &operator<<=(const size_t shift) noexcept;
    inline SecureBuffer<N> &operator+=(const SecureBuffer<N> &op) noexcept
        {std::transform(data_, data_ + N, op.data_, data_, std::bit_xor<uint8_t>()); return *this;}
    inline SecureBuffer<N> &operator+=(const uint8_t (&op)[N]) noexcept
        {std::transform(data_, data_ + N, op, data_, std::bit_xor<uint8_t>()); return *this;}
    struct Iterator;
    inline Iterator begin() noexcept { return Iterator(data_); }
    inline Iterator end() noexcept { return Iterator(data_ + N); }
    struct ConstIterator;
    inline ConstIterator begin() const noexcept { return ConstIterator(data_); }
    inline ConstIterator end() const noexcept { return ConstIterator(data_ + N); }
    SecureBuffer<N> &add(const size_t num);
};

template <size_t N>
SecureBuffer<N>::SecureBuffer() {
    if (mlock(data_, N))
        throw std::bad_alloc();
}

template <typename... Ts>
SecureBuffer(Ts...) -> SecureBuffer<sizeof...(Ts)>;

template <size_t N>
SecureBuffer<N>::SecureBuffer(std::initializer_list<uint8_t> init) : SecureBuffer() {
    std::copy(init.begin(), init.end(), data_);
}

template <size_t N>
SecureBuffer<N>::SecureBuffer(const SecureBuffer &original) noexcept : SecureBuffer() {
    std::copy(original.data_, original.data_ + N, data_);
}

template <size_t N>
SecureBuffer<N>::SecureBuffer(SecureBuffer &&original) : SecureBuffer() {
    std::copy(original.data_, original.data_ + N, data_);
    original.zero();
}

template <size_t N>
SecureBuffer<N>::~SecureBuffer() noexcept {
    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    thread_local std::uniform_int_distribution dist(0, 255);
    
    for (size_t i = 0; i < N; ++i)
        data_[i] = static_cast<uint8_t>(dist(gen));
    munlock(data_, N);
}

template <size_t N>
SecureBuffer<N> &SecureBuffer<N>::operator<<=(const size_t shift) noexcept {
    if (shift == 0) return *this;
    const size_t total_bits = N * 8;
    if (shift >= total_bits) {
        this->zero();
        return *this;
    }
    const size_t byte_shift = shift / 8;
    const size_t bit_shift = shift % 8;
    if (byte_shift > 0) {
        for (size_t i = 0; i < N - byte_shift; ++i)
            (*this)[i] = (*this)[i + byte_shift];
        std::fill(data_ + N - byte_shift, data_ + N, 0);
    }
    if (bit_shift > 0) {
        for (size_t i = 0; i < N - 1; ++i) {
            (*this)[i] = ((*this)[i] << bit_shift) | ((*this)[i + 1] >> (8 - bit_shift));
        }
        (*this)[N - 1] <<= bit_shift;
    }
    return *this;
}


#ifndef SECUREBUFFER_BIG_ENDIAN_CONTER
template<size_t N>
SecureBuffer<N> &SecureBuffer<N>::add(size_t num) {
    uint16_t carry = 0;
    size_t i = 0;
    for (; i < std::min(sizeof(size_t), N) && num; ++i) {
        carry = static_cast<uint16_t>(
            static_cast<uint16_t>(data_[i]) +
            static_cast<uint16_t>(num & 0xFF) +
            (carry >> 8)
        );
        data_[i] = static_cast<uint8_t>(carry);
        num >>= 8;
    }
    carry >>= 8;
    for (; i < N && carry; ++i) {
        carry =
            static_cast<uint16_t>(data_[i]) +
            carry;
        data_[i] = static_cast<uint8_t>(carry);
        carry >>= 8;
    }
    return *this;
}
#else
template<size_t N>
SecureBuffer<N> &SecureBuffer<N>::add(size_t num) {
    uint16_t carry = 0;
    size_t i = 0;
    for (; i < std::min(sizeof(size_t), N) && num; ++i) {
        carry = static_cast<uint16_t>(
            static_cast<uint16_t>(data_[N - 1 - i]) +
            static_cast<uint16_t>(num & 0xFF) +
            (carry >> 8)
        );
        data_[N - 1 - i] = static_cast<uint8_t>(carry);
        num >>= 8;
    }
    carry >>= 8;
    for (; i < N && carry; ++i) {
        carry =
            static_cast<uint16_t>(data_[N - 1 - i]) +
            carry;
        data_[N - 1 - i] = static_cast<uint8_t>(carry);
        carry >>= 8;
    }
    return *this;
}
#endif

template<size_t N>
struct SecureBuffer<N>::Iterator {
    using iterator_category = std::random_access_iterator_tag;
    using difference_type   = std::ptrdiff_t;
    using value_type        = uint8_t;
    using pointer           = uint8_t *;
    using reference         = uint8_t &;

    Iterator(const pointer ptr) noexcept : ptr_(ptr) {}
    inline reference operator*() const noexcept { return *ptr_; }
    inline pointer operator->() const noexcept { return ptr_; }
    inline Iterator& operator++() noexcept { ++ptr_; return *this; }  
    inline Iterator operator++(int) noexcept { Iterator tmp = *this; ++(*this); return tmp; }
    inline Iterator& operator--() noexcept { --ptr_; return *this; }  
    inline Iterator operator--(int) noexcept { Iterator tmp = *this; --(*this); return tmp; }
    inline bool operator==(const Iterator& b) const noexcept { return ptr_ == b.ptr_; }
    inline bool operator!=(const Iterator& b) const noexcept { return ptr_ != b.ptr_; }
    inline bool operator<(const Iterator& b) const noexcept { return ptr_ < b.ptr_; }
    inline bool operator>(const Iterator& b) const noexcept { return ptr_ > b.ptr_; }
    inline bool operator<=(const Iterator& b) const noexcept { return ptr_ <= b.ptr_; }
    inline bool operator>=(const Iterator& b) const noexcept { return ptr_ >= b.ptr_; }
    inline Iterator &operator+=(size_t n) noexcept { ptr_ += n; return *this; }
    inline Iterator &operator-=(size_t n) noexcept { ptr_ -= n; return *this; }
    inline Iterator operator+(size_t n) const noexcept { return Iterator(ptr_ + n); }
    inline Iterator operator-(size_t n) const noexcept { return Iterator(ptr_ - n); }
    inline difference_type operator-(const Iterator &b) const noexcept {return ptr_ - b.ptr_; }
private:
    pointer ptr_;
};

template<size_t N>
struct SecureBuffer<N>::ConstIterator {
    using iterator_category = std::random_access_iterator_tag;
    using difference_type   = std::ptrdiff_t;
    using value_type        = uint8_t;
    using pointer           = const uint8_t *;
    using reference         = const uint8_t &;

    ConstIterator(pointer ptr) noexcept : ptr_(ptr) {}
    inline reference operator*() const noexcept { return *ptr_; }
    inline pointer operator->() const noexcept { return ptr_; }
    inline ConstIterator& operator++() noexcept { ++ptr_; return *this; }  
    inline ConstIterator operator++(int) noexcept { ConstIterator tmp = *this; ++(*this); return tmp; }
    inline ConstIterator& operator--() noexcept { --ptr_; return *this; }  
    inline ConstIterator operator--(int) noexcept { ConstIterator tmp = *this; --(*this); return tmp; }
    inline bool operator==(const ConstIterator& b) const noexcept { return ptr_ == b.ptr_; }
    inline bool operator!=(const ConstIterator& b) const noexcept { return ptr_ != b.ptr_; }
    inline bool operator<(const ConstIterator& b) const noexcept { return ptr_ < b.ptr_; }
    inline bool operator>(const ConstIterator& b) const noexcept { return ptr_ > b.ptr_; }
    inline bool operator<=(const ConstIterator& b) const noexcept { return ptr_ <= b.ptr_; }
    inline bool operator>=(const ConstIterator& b) const noexcept { return ptr_ >= b.ptr_; }   
    inline ConstIterator &operator+=(size_t n) noexcept { ptr_ += n; return *this; }
    inline ConstIterator &operator-=(size_t n) noexcept { ptr_ -= n; return *this; }
    inline ConstIterator operator+(size_t n) const noexcept { return ConstIterator(ptr_ + n); }
    inline ConstIterator operator-(size_t n) const noexcept { return ConstIterator(ptr_ - n); }
    inline difference_type operator-(const ConstIterator &b) const noexcept {return ptr_ - b.ptr_; }
private:
    pointer ptr_;
};

#endif