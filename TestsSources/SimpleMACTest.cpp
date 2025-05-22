#include <gtest/gtest.h>
#include <array>
#include "SimpleMAC.hpp"

TEST(SimpleMACTest, FullBlocks) {
    SecureBuffer<32> key;
    std::fill(key.begin(), key.end(), 0xAA);
    std::array<uint8_t, 64> text;
    std::fill(text.begin(), text.begin() + 32, 0xBB);
    std::fill(text.begin() + 32, text.end(), 0xCC);
    std::array<uint8_t, 32> expected_digest;
    std::fill(expected_digest.begin(), expected_digest.end(), 0xAA ^ 0xBB ^ 0xCC);

    SimpleMAC mac(key);
    mac.update(text.data(), 64);
    std::array<uint8_t, 32> digest;
    mac.digest(digest.data());

    EXPECT_EQ(digest, expected_digest);
}

TEST(SimpleMACTest, NotFullBlocks) {
    SecureBuffer<32> key;
    std::fill(key.begin(), key.end(), 0xAA);
    std::array<uint8_t, 48> text;
    std::fill(text.begin(), text.begin() + 32, 0xBB);
    std::fill(text.begin() + 32, text.end(), 0xCC);
    std::array<uint8_t, 32> expected_digest;
    std::fill(expected_digest.begin(), expected_digest.begin() + 16, 0xAA ^ 0xBB ^ 0xCC);
    std::fill(expected_digest.begin() + 16, expected_digest.end(), 0xAA ^ 0xBB);

    SimpleMAC mac(key);
    mac.update(text.data(), 48);
    std::array<uint8_t, 32> digest;
    mac.digest(digest.data());

    EXPECT_EQ(digest, expected_digest);
}

TEST(SimpleMACTest, Clear) {
    SecureBuffer<32> key;
    std::fill(key.begin(), key.end(), 0xAA);
    std::array<uint8_t, 48> text;
    std::fill(text.begin(), text.begin() + 32, 0xBB);
    std::fill(text.begin() + 32, text.end(), 0xCC);
    std::array<uint8_t, 32> expected_digest;
    std::fill(expected_digest.begin(), expected_digest.begin() + 16, 0xAA ^ 0xBB ^ 0xCC);
    std::fill(expected_digest.begin() + 16, expected_digest.end(), 0xAA ^ 0xBB);

    SimpleMAC mac(key);
    mac.update(text.data(), 48);
    std::array<uint8_t, 32> digest;
    mac.digest(digest.data());
    mac.clear();
    mac.update(text.data(), 48);
    mac.digest(digest.data());

    EXPECT_EQ(digest, expected_digest);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}