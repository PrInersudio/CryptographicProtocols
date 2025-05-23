#include <netinet/in.h>
#include <sys/socket.h>
#include <stdexcept>
#include "TCPServer.hpp"

TCPServer::TCPServer(const uint16_t port) {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0)
        throw std::runtime_error("Не удалось открыть сокет сервера.");
    struct sockaddr_in servaddr = {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    if (bind(sockfd_, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr)))
        throw std::runtime_error("Не удалался bind сокета сервера.");
    if (listen(sockfd_, 5))
        throw std::runtime_error("Сервер не смог начать прослушивание.");
}

std::vector<uint8_t> TCPServer::getMsg() {
    static constexpr size_t MAX_SIZE = 10 * 1024 * 1024; // максимум 10 МБ
    static constexpr size_t BUF_SIZE = 2048;
    
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);
    int connfd = accept(sockfd_, reinterpret_cast<struct sockaddr *>(&cli), &len);
    if (connfd < 0)
        throw std::runtime_error("Не удалось принять соединение.");
    std::vector<uint8_t> result;
    try {
        uint8_t buffer[BUF_SIZE];
        ssize_t n;
        while ((n = read(connfd, buffer, BUF_SIZE)) > 0) {
            if (result.size() + n > MAX_SIZE)
                throw std::runtime_error("Превышен максимальный размер сообщения.");
            result.insert(result.end(), buffer, buffer + n);
        }
    } catch (const std::exception &e) {
        close(connfd);
        throw;
    }
    close(connfd);
    return result;
}