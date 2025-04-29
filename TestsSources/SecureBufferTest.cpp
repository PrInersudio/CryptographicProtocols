#include <gtest/gtest.h>
#include "SecureBuffer.hpp"

TEST(SecureBufferTest, InitializerListConstructor) {
    SecureBuffer buffer = {1, 2, 3, 4};
    EXPECT_EQ(buffer[0], 1);
    EXPECT_EQ(buffer[1], 2);
    EXPECT_EQ(buffer[2], 3);
    EXPECT_EQ(buffer[3], 4);
}

TEST(SecureBufferTest, CopyConstructor) {
    SecureBuffer buffer1 = {5, 6, 7, 8};
    SecureBuffer buffer2 = buffer1;
    EXPECT_EQ(buffer1, buffer2);
}

TEST(SecureBufferTest, AssignmentOperator) {
    SecureBuffer buffer1 = {1, 2, 3, 4};
    SecureBuffer<4> buffer2;
    buffer2 = buffer1;
    EXPECT_EQ(buffer1, buffer2);
}

TEST(SecureBufferTest, EqualityOperator) {
    SecureBuffer buffer1 = {9, 8, 7, 6};
    SecureBuffer buffer2 = {9, 8, 7, 6};
    SecureBuffer buffer3 = {6, 7, 8, 9};
    EXPECT_TRUE(buffer1 == buffer2);
    EXPECT_FALSE(buffer1 == buffer3);
}

TEST(SecureBufferTest, RawPointerAccess) {
    SecureBuffer buffer = {10, 20, 30, 40};
    uint8_t* raw = buffer.raw();
    ASSERT_NE(raw, nullptr);
    EXPECT_EQ(raw[0], 10);
    EXPECT_EQ(raw[1], 20);
    EXPECT_EQ(raw[2], 30);
    EXPECT_EQ(raw[3], 40);
}

TEST(SecureBufferTest, ZeroFunction) {
    SecureBuffer buffer = {1, 2, 3, 4};
    buffer.zero();
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(buffer[i], 0);
    }
}

TEST(SecureBufferTest, LeftShiftOperator_NoShift) {
    SecureBuffer buffer = {1, 2, 3, 4};
    buffer <<= 0;
    EXPECT_EQ(buffer[0], 1);
    EXPECT_EQ(buffer[1], 2);
    EXPECT_EQ(buffer[2], 3);
    EXPECT_EQ(buffer[3], 4);
}

TEST(SecureBufferTest, LeftShiftOperator_SmallShift) {
    SecureBuffer buffer = {0b00000000, 0b11111111};
    buffer <<= 4;
    EXPECT_EQ(buffer[0], 0b00001111);
    EXPECT_EQ(buffer[1], 0b11110000);
}

TEST(SecureBufferTest, LeftShiftOperator_LargeShift) {
    SecureBuffer buffer = {0xFF, 0xFF};
    buffer <<= 16;
    for (size_t i = 0; i < 2; ++i) {
        EXPECT_EQ(buffer[i], 0);
    }
}

TEST(SecureBufferTest, AdditionOperator) {
    SecureBuffer buffer1 = {0b10101010, 0b01010101};
    SecureBuffer buffer2 = {0b11110000, 0b00001111};
    buffer1 += buffer2;
    EXPECT_EQ(buffer1[0], uint8_t(0b01011010));
    EXPECT_EQ(buffer1[1], uint8_t(0b01011010));
}

TEST(SecureBufferIteratorTest, BasicDereferenceAndIncrement) {
    SecureBuffer buf = {1, 2, 3, 4, 5};
    auto it = buf.begin();
    EXPECT_EQ(*it, 1);
    ++it;
    EXPECT_EQ(*it, 2);
    it++;
    EXPECT_EQ(*it, 3);
    --it;
    EXPECT_EQ(*it, 2);
    it--;
    EXPECT_EQ(*it, 1);
}

TEST(SecureBufferIteratorTest, EqualityAndInequality) {
    SecureBuffer buf = {10, 20, 30};
    auto it1 = buf.begin();
    auto it2 = buf.begin();
    auto it3 = buf.end();
    EXPECT_TRUE(it1 == it2);
    EXPECT_TRUE(it1 != it3);
    ++it1;
    EXPECT_TRUE(it1 != it2);
    it1 += 2;
    EXPECT_TRUE(it1 == it3);
}

TEST(SecureBufferIteratorTest, AdditionAndSubtractionOperators) {
    SecureBuffer buf = {5, 6, 7, 8};
    auto it = buf.begin();
    it += 2;
    EXPECT_EQ(*it, 7);
    it -= 1;
    EXPECT_EQ(*it, 6);
    auto it2 = it + 2;
    EXPECT_EQ(*it2, 8);
    auto it3 = it2 - 2;
    EXPECT_EQ(*it3, 6);
}

TEST(SecureBufferIteratorTest, DifferenceOperator) {
    SecureBuffer buf = {0, 1, 2, 3, 4, 5};
    auto it1 = buf.begin();
    auto it2 = it1 + 4;
    EXPECT_EQ(it2 - it1, 4);
}

TEST(SecureBufferIteratorTest, ModifyThroughIterator) {
    SecureBuffer buf = {1, 1, 1};
    auto it = buf.begin();
    *it = 10;
    ++it;
    *it = 20;
    ++it;
    *it = 30;
    EXPECT_EQ(buf[0], 10);
    EXPECT_EQ(buf[1], 20);
    EXPECT_EQ(buf[2], 30);
}

TEST(SecureBufferIteratorTest, FullIteration) {
    SecureBuffer buf = {2, 4, 6, 8};
    int expected[] = {2, 4, 6, 8};
    size_t idx = 0;
    for (auto it = buf.begin(); it != buf.end(); ++it) {
        EXPECT_EQ(*it, expected[idx]);
        ++idx;
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}