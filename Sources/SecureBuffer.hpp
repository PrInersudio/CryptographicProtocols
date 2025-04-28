#ifndef SECURE_BUFFER_HPP
#define SECURE_BUFFER_HPP

#include <stdlib.h>
#include <cinttypes>
#include <string.h>
#include <sys/mman.h>
#include <stdexcept>

template <size_t N>
class SecureBuffer {
private:
    uint8_t data_[N];
public:
    SecureBuffer();
    SecureBuffer(std::initializer_list<uint8_t> init);
    SecureBuffer(const SecureBuffer &);
    SecureBuffer& operator=(const SecureBuffer &);
    ~SecureBuffer();
    uint8_t &operator[](const size_t i);
    const uint8_t &operator[](const size_t i) const;
    bool operator==(const SecureBuffer &other) const;
    uint8_t *raw();
    const uint8_t *raw() const;
    void zero();
    SecureBuffer<N> &operator<<=(const size_t shift);
    SecureBuffer<N> &operator+=(const SecureBuffer<N> &op);
    template<typename InputIt>
    void insert(InputIt first, InputIt last, size_t pos = 0);
    template<typename Container>
    void insert(const Container& container, size_t pos = 0);
    class Iterator;
    Iterator begin();
    Iterator end();
};

template <size_t N>
SecureBuffer<N>::SecureBuffer() {
    if (mlock(data_, N))
        throw std::bad_alloc();
}

template <size_t N>
SecureBuffer<N>::SecureBuffer(std::initializer_list<uint8_t> init) : SecureBuffer() {
    if (init.size() > N)
        throw std::out_of_range
            ("Слишком большой размер листа инициализации для SecureBuffer<" + std::to_string(N) + ">.");
    std::copy(init.begin(), init.end(), data_);
    std::fill(data_ + init.size(), data_ + N, 0);
}

template <size_t N>
SecureBuffer<N>::SecureBuffer(const SecureBuffer &original) : SecureBuffer() {
    memcpy(data_, original.data_, N);
}

template <size_t N>
SecureBuffer<N> &SecureBuffer<N>::operator=(const SecureBuffer &other) {
    if (this != &other)
        memcpy(data_, other.data_, N);
    return *this;
}

template <size_t N>
SecureBuffer<N>::~SecureBuffer() {
    explicit_bzero(data_, N);
    munlock(data_, N);
}

template <size_t N>
uint8_t &SecureBuffer<N>::operator[](const size_t i) {
    return data_[i];
}

template <size_t N>
const uint8_t &SecureBuffer<N>::operator[](const size_t i) const {
    return data_[i];
}

template <size_t N>
bool SecureBuffer<N>::operator==(const SecureBuffer &other) const {
    return !memcmp(data_, other.data_, N);
}

template <size_t N>
uint8_t *SecureBuffer<N>::raw() {
    return data_;
}

template <size_t N>
const uint8_t *SecureBuffer<N>::raw() const {
    return data_;
}

template <size_t N>
void SecureBuffer<N>::zero() {
    explicit_bzero(data_, N);
}

template <size_t N>
SecureBuffer<N> &SecureBuffer<N>::operator<<=(const size_t shift) {
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
        for (size_t i = N - byte_shift; i < N; ++i)
            (*this)[i] = 0;
    }
    if (bit_shift > 0) {
        const size_t end = N - byte_shift - 1;
        for (size_t i = 0; i < end; ++i)
            (*this)[i] = ((*this)[i] << bit_shift) | ((*this)[i + 1] >> (8 - bit_shift));
        (*this)[end] <<= bit_shift;
    }
    return *this;
}

template <size_t N>
SecureBuffer<N> &SecureBuffer<N>::operator+=(const SecureBuffer<N> &op) {
    for (uint8_t i = 0; i < N; ++i) (*this)[i] ^= op[i];
    return *this;
}

template<size_t N>
template<typename InputIt>
void SecureBuffer<N>::insert(InputIt first, InputIt last, size_t pos) {
    for (; pos <  N && first != last; ++pos) {
        data_[pos] = *first;
        ++first;
    }
}

template<size_t N>
template<typename Container>
void SecureBuffer<N>::insert(const Container& container, size_t pos) {
    insert(std::begin(container), std::end(container), pos);
}

template<size_t N>
struct SecureBuffer<N>::Iterator {
    using iterator_category = std::forward_iterator_tag;
    using difference_type   = std::ptrdiff_t;
    using value_type        = uint8_t;
    using pointer           = uint8_t *;
    using reference         = uint8_t &;

    Iterator(const pointer ptr) : ptr_(ptr) {}
    reference operator*() const { return *ptr_; }
    pointer operator->() const { return ptr_; }
    Iterator& operator++() { ++ptr_; return *this; }  
    Iterator operator++(int) { Iterator tmp = *this; ++(*this); return tmp; }
    Iterator& operator--() { --ptr_; return *this; }  
    Iterator operator--(int) { Iterator tmp = *this; --(*this); return tmp; }
    bool operator==(const Iterator& b) const { return ptr_ == b.ptr_; }
    bool operator!=(const Iterator& b) const { return ptr_ != b.ptr_; }   
    Iterator &operator+=(size_t n) { ptr_ += n; return *this; }
    Iterator &operator-=(size_t n) { ptr_ -= n; return *this; }
    Iterator operator+(size_t n) const { return Iterator(ptr_ + n); }
    Iterator operator-(size_t n) const { return Iterator(ptr_ - n); }
    size_t operator-(const Iterator &b) const {return ptr_ - b.ptr_; }
private:
    pointer ptr_;
};

template<size_t N>
SecureBuffer<N>::Iterator SecureBuffer<N>::begin() {
    return Iterator(data_);
}

template<size_t N>
SecureBuffer<N>::Iterator SecureBuffer<N>::end() {
    return Iterator(data_ + N);
}

#endif