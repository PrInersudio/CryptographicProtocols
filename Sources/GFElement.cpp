#include "GFElement.hpp"

GFElement::GFElement(const uint8_t num) : num_(num) {}

GFElement::operator uint8_t() const {
    return num_;
}

GFElement &GFElement::operator+=(const uint8_t other) {
    num_ ^= other;
    return *this;
}
GFElement &GFElement::operator+=(const GFElement &other) {
    return *this += other.num_;
}

GFElement GFElement::operator+(const uint8_t other) const {
    GFElement result = *this;
    result += other;
    return result;
}

GFElement GFElement::operator+(const GFElement &other) const {
    return *this + other.num_;
}

GFElement operator+(const uint8_t num, const GFElement &element) {
    return element + num;
}

GFElement &GFElement::operator*=(uint8_t other) {
    #include "MulTable.hpp"
    num_ = mul_table[num_][other];
    return *this;
}

GFElement &GFElement::operator*=(const GFElement &other) {
    return *this *= other.num_;
}

GFElement GFElement::operator*(const uint8_t other) const {
    GFElement result = *this;
    result *= other;
    return result;
}

GFElement GFElement::operator*(const GFElement &other) const {
    return *this * other.num_;
}

GFElement operator*(const uint8_t num, const GFElement &element) {
    return element * num;
}

bool GFElement::operator==(const uint8_t other) const {
    return num_ == other;
}

bool GFElement::operator==(const GFElement &other) const {
    return this->num_ == other.num_;
}

bool operator==(const uint8_t num, const GFElement &element) {
    return num == element.num_;
}