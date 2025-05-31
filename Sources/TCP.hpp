#ifndef TCP_HPP
#define TCP_HPP

#include <cinttypes>
#include <vector>
#include <string>
#include <unistd.h>
#include <easylogging++.h>
#include <sys/socket.h>

class TCP {
protected:
    static constexpr size_t MAX_RECV_SIZE = 10 * 1024 * 1024; // максимум 10 МБ
    static constexpr size_t RECV_BUF_SIZE = 2048;

    mutable std::mutex read_mutex_;
    mutable std::mutex write_mutex_;
public:
    virtual std::vector<uint8_t> operator()(const size_t size) const = 0;
    virtual void operator()(const std::vector<uint8_t> &data) const = 0;
    virtual void close() = 0;
    virtual ~TCP() = default;
};

class TCPServer : public TCP {
private:
    int sockfd_;
    int connfd_;
public:
    TCPServer(const uint16_t port);
    void accept(const std::string &client_ip);
    inline void close() noexcept override
        { if (sockfd_ >= 0) { shutdown(sockfd_, SHUT_RDWR); ::close(sockfd_); sockfd_ = -1; } if (connfd_ >= 0) { shutdown(connfd_, SHUT_RDWR); ::close(connfd_); connfd_ = -1; } LOG(INFO) << "Сервер закрыт";  }
    inline ~TCPServer() noexcept { close(); }
    std::vector<uint8_t> operator()(const size_t size) const override;
    void operator()(const std::vector<uint8_t> &data) const override;

    TCPServer(const TCPServer &) = delete;
    TCPServer &operator=(const TCPServer &) = delete;
    inline TCPServer(TCPServer &&original) noexcept : sockfd_(original.sockfd_), connfd_(original.connfd_)
        { original.sockfd_ = -1; original.connfd_ = -1; }
    TCPServer &operator=(TCPServer &&) = delete;
};

class TCPClient : public TCP {
private:
    int sockfd_;
public:
    TCPClient();
    void connect(const std::string &server_ip, const uint16_t server_port) const;
    inline void close() noexcept override { if (sockfd_ >= 0) { shutdown(sockfd_, SHUT_RDWR); ::close(sockfd_); sockfd_ = -1; } LOG(INFO) << "Клиент закрыт"; }
    inline ~TCPClient() noexcept { close(); }
    void operator()(const std::vector<uint8_t> &data) const override;
    std::vector<uint8_t> operator()(const size_t size) const override;

    TCPClient(const TCPClient &) = delete;
    TCPClient &operator=(const TCPClient &) = delete;
    inline TCPClient(TCPClient &&original) noexcept : sockfd_(original.sockfd_)
        { original.sockfd_ = -1; }
    TCPClient &operator=(TCPClient &&) = delete;
};

#endif