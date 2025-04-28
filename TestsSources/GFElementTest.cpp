#include <gtest/gtest.h>
#include "GFElement.hpp"

TEST(GFElementTest, ConstructorAndConversionZero) {
    EXPECT_EQ(uint8_t(GFElement(0U)), 0U);
}

TEST(GFElementTest, ConstructorAndConversionMax) {
    EXPECT_EQ(uint8_t(GFElement(0xFFU)), 0xFFU);
}

TEST(GFElementTest, ConstructorAndConversionGeneral) {
    EXPECT_EQ(uint8_t(GFElement(5U)), 5U);
}

TEST(GFElementTest, AdditionAssignmentUInt8) {
    GFElement a(0xFF);
    a += 0x0FU;
    EXPECT_EQ(a, 0xF0U);
}

TEST(GFElementTest, AdditionUInt8Right) {
    EXPECT_EQ(GFElement(0xFF) + 0x0F, 0xF0U);
}

TEST(GFElementTest, AdditionUInt8Left) {
    EXPECT_EQ(0x0FU + GFElement(0xFFU), 0xF0U);
}

TEST(GFElementTest, AdditionAssignmentGFElement) {
    GFElement a(0xFFU);
    a += GFElement(0x0FU);
    EXPECT_EQ(a, 0xF0U);
}

TEST(GFElementTest, AdditionGFElement) {
    EXPECT_EQ(GFElement(0xFFU) + GFElement(0x0FU), 0xF0U);
}

TEST(GFElementTest, MultiplicationAssignmentUInt8General) {
    GFElement a(2U);
    a *= 3U;
    EXPECT_EQ(a, 6U);
}

TEST(GFElementTest, MultiplicationAssignmentUInt8Overflow) {
    GFElement a(0x80U);
    a *= 0x02U;
    EXPECT_EQ(a, 0xC3U);
}

TEST(GFElementTest, MultiplicationAssignmentGFElementGeneral) {
    GFElement a(2U);
    a *= GFElement(3U);
    EXPECT_EQ(a, 6U);
}

TEST(GFElementTest, MultiplicationAssignmentGFElementOverflow) {
    GFElement a(0x80U);
    a *= GFElement(0x02U);
    EXPECT_EQ(a, 0xC3U);
}

TEST(GFElementTest, MultiplicationUInt8RightGeneral) {
    EXPECT_EQ(GFElement(2U) * 3U, 6U);
}

TEST(GFElementTest, MultiplicationUInt8RightOverflow) {
    EXPECT_EQ(GFElement(0x80U) * 0x02U, 0xC3U);
}

TEST(GFElementTest, MultiplicationUInt8LeftGeneral) {
    EXPECT_EQ(3U * GFElement(2U), 6U);
}

TEST(GFElementTest, MultiplicationUInt8LeftOverflow) {
    EXPECT_EQ(0x02U * GFElement(0x80U), 0xC3U);
}

TEST(GFElementTest, MultiplicationGFElementGeneral) {
    EXPECT_EQ(GFElement(2U) * GFElement(3U), 6U);
}

TEST(GFElementTest, MultiplicationGFElementOverflow) {
    EXPECT_EQ(GFElement(0x80U) * GFElement(0x02U), 0xC3U);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}