#ifndef LAB1_UTILS_HPP
#define LAB1_UTILS_HPP

#include "Kuznechik.hpp"
#include "OMAC.hpp"

#define BUFFER_SIZE 8192


void checkTimestamp(const uint64_t timestamp_raw) noexcept;
void initKuznechikOMACCTX(OMAC<Kuznechik> &ctx, const char *filename);
bool checkModeParam(const char *mode_param, bool &encrypt);
std::vector<uint8_t> parseHexString(const std::string& hex);
std::string toHexString(const std::vector<uint8_t> &data) noexcept;
bool fillBuffer(std::ifstream &file, std::vector<uint8_t> &buffer) noexcept;

#endif