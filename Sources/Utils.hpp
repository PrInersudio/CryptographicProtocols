#ifndef LAB1_UTILS_HPP
#define LAB1_UTILS_HPP

#include "Kuznechik.hpp"
#include "OMAC.hpp"

#define BUFFER_SIZE 65536


void checkTimestamp(const uint64_t timestamp_raw) noexcept;
void getAndCheckKey(const char *filename, MasterKeySecureBuffer<32> &key);
void initKuznechikOMACCTX(OMAC<Kuznechik> &ctx, const char *filename);
bool checkModeParam(const char *mode_param, bool &encrypt);
std::vector<uint8_t> parseHexString(const std::string& hex);
std::string toHexString(const std::vector<uint8_t> &data) noexcept;
bool fillBuffer(std::ifstream &file, std::vector<uint8_t> &buffer) noexcept;

inline void confLog(bool stdout_logging = false, bool file_loging = false, const char *logfile = nullptr) noexcept {
    el::Configurations conf;
    conf.setToDefault();
    conf.set(el::Level::Global, el::ConfigurationType::ToFile, file_loging ? "true" : "false");
    conf.set(el::Level::Global, el::ConfigurationType::ToStandardOutput, stdout_logging ? "true" : "false");
    conf.set(el::Level::Global, el::ConfigurationType::Filename, logfile == nullptr ? "/dev/null" : std::string(logfile));
    conf.set(el::Level::Global, el::ConfigurationType::Format, "[%datetime] %level: %msg");
    el::Loggers::reconfigureLogger("default", conf);
}

#endif