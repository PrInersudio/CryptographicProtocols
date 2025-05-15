#include "SecureBuffer.hpp"
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <iomanip>

int main() {
    {
        SecureBuffer<16> buf;
        std::cout << "Pid: " << getpid() << std::endl;
        std::cout << "Buf pointer: " << reinterpret_cast<void *>(buf.raw()) << std::endl;
        std::fill(buf.begin(), buf.end(), 0xAA);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t i = 0; i < 16; ++i)
            oss << std::setw(2) << static_cast<int>(buf[i]);
        std::cout << "Buf content: " << oss.str() << std::endl;
    }
    std::cout << "Область видимости SecureBuffer закончена." << std::endl;
    return 0;
}