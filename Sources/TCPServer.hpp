#ifndef TCP_SERVER_HPP
#define TCP_SERVER_HPP

#include <cinttypes>
#include <vector>
#include <unistd.h>

class TCPServer {
private:
    int sockfd_;
public:
    TCPServer(const uint16_t port);
    inline ~TCPServer() { close(sockfd_); }
    std::vector<uint8_t> getMsg();
};

#endif