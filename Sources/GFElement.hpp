#ifndef GFELEMENT_HPP
#define GFELEMENT_HPP

#include <cinttypes>

class GFElement {
private:
    uint8_t num_;
public:
    GFElement(const uint8_t num);
    explicit operator uint8_t() const;
    GFElement &operator+=(const uint8_t other);
    GFElement &operator+=(const GFElement &other);
    GFElement operator+(const uint8_t other) const;
    GFElement operator+(const GFElement &other) const;
    friend GFElement operator+(const uint8_t num, const GFElement &element);
    GFElement &operator*=(uint8_t other);
    GFElement &operator*=(const GFElement &other);
    GFElement operator*(const uint8_t other) const;
    GFElement operator*(const GFElement &other) const;
    friend GFElement operator*(const uint8_t num, const GFElement &element);
    bool operator==(const uint8_t other) const;
    bool operator==(const GFElement &other) const;
    friend bool operator==(const uint8_t num, const GFElement &element);
};

#endif