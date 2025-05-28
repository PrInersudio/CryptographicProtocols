#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdexcept>
#include "TCP.hpp"

TCPServer::TCPServer(const uint16_t port) {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0)
        throw std::runtime_error("Не удалось открыть сокет сервера.");
    LOG(INFO) << "Инициализирована структра сокета сервера";
    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    if (bind(sockfd_, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr))) {
        close(sockfd_);
        throw std::runtime_error("Не удался bind сокета сервера.");
    }
    LOG(INFO) << "Сервер прикреплён к порту " << port;
    if (listen(sockfd_, 5)) {
        close(sockfd_);
        throw std::runtime_error("Сервер не смог начать прослушивание.");
    }
    LOG(INFO) << "Сервер начал прослушивание на порту " << port;
}

void TCPServer::accept(const std::string &client_ip) {
    in_addr clientaddr{};
    if (inet_pton(AF_INET, client_ip.c_str(), &clientaddr) <= 0)
        throw std::invalid_argument("Некорректный IP-адрес клиента.");
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);
    connfd_ = ::accept(sockfd_, reinterpret_cast<struct sockaddr *>(&cli), &len);
    if (connfd_ < 0) {
        close(sockfd_);
        throw std::runtime_error("Не удалось принять соединение.");
    }
    if (cli.sin_addr.s_addr != clientaddr.s_addr) {
        close(sockfd_);
        close(connfd_);
        throw std::runtime_error("Попытка подключения с неизвестного ip адреса.");
    }
    LOG(INFO) << "Сервер успешно принял подключение к " << client_ip;
}

std::vector<uint8_t> TCPServer::operator()(const size_t size) const {
    if (size > MAX_RECV_SIZE) throw std::runtime_error("Недопустимый размер сообщения.");
    if (sockfd_ < 0) throw std::runtime_error("Сокет сервера был перемещён из данного объекта.");
    if (connfd_ < 0)
        throw std::runtime_error("Нет активного соединения для чтения.");
    std::vector<uint8_t> result;
    uint8_t buffer[RECV_BUF_SIZE];
    ssize_t n;
    size_t total = 0;
    while (total < size) {
        n = read(connfd_, buffer, std::min(RECV_BUF_SIZE, size - total));
        if (n <= 0) {
            if (errno != EINTR)
                throw std::runtime_error("Ошибка при получении данных.");
            else continue;
        }
        total += n;
        result.insert(result.end(), buffer, buffer + n);
    }
    LOG(INFO) << "Сервер принял сообщение размера " << size;
    return result;
}

void TCPServer::operator()(const std::vector<uint8_t> &data) const {
    if (sockfd_ < 0) throw std::runtime_error("Сокет сервера был перемещён из данного объекта.");
    if (connfd_ < 0) throw std::runtime_error("Нет активного соединения для отправки.");
    if (data.size() > MAX_RECV_SIZE) throw std::runtime_error("Превышен максимальный размер сообщения.");
    size_t total = 0;
    ssize_t n;
    while (total < data.size()) {
        n = write(connfd_, data.data() + total, data.size() - total);
        if (n <= 0  && errno != EINTR) throw std::runtime_error("Ошибка при отправке данных.");
        total += n;
    }
    LOG(INFO) << "Сервер отправил сообщение размера " << data.size();
}

TCPClient::TCPClient() {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0)
        throw std::runtime_error("Не удалось открыть сокет клиента.");
    LOG(INFO) << "Инициализирована структра сокета клиента";
}

void TCPClient::connect(const std::string &server_ip, const uint16_t server_port) const {
    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip.c_str(), &servaddr.sin_addr) <= 0)
        throw std::runtime_error("Некорректный IP-адрес сервера.");
    servaddr.sin_port = htons(server_port);
    if (::connect(sockfd_, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr)))
        throw std::runtime_error("Не удалось подключиться к серверу.");
    LOG(INFO) << "Клиент успешно подключился к " << server_ip;
}

std::vector<uint8_t> TCPClient::operator()(const size_t size) const {
    if (size > MAX_RECV_SIZE) throw std::runtime_error("Недопустимый размер сообщения.");
    if (sockfd_ < 0) throw std::runtime_error("Сокет был перемещён из данного объекта.");
    std::vector<uint8_t> result;
    uint8_t buffer[RECV_BUF_SIZE];
    ssize_t n;
    size_t total = 0;
    while (total < size) {
        n = read(sockfd_, buffer, std::min(RECV_BUF_SIZE, size - total));
        if (n <= 0) {
            if (errno != EINTR)
                throw std::runtime_error("Ошибка при получении данных.");
            else continue;
        }
        total += n;
        result.insert(result.end(), buffer, buffer + n);
    }
    LOG(INFO) << "Клиент принял сообщение размера " << size;
    return result;
}

void TCPClient::operator()(const std::vector<uint8_t> &data) const {
    if (sockfd_ < 0) throw std::runtime_error("Сокет был перемещён из данного объекта.");
    if (data.size() > MAX_RECV_SIZE) throw std::runtime_error("Превышен максимальный размер сообщения.");
    size_t total = 0;
    ssize_t n;
    while (total < data.size()) {
        n = write(sockfd_, data.data() + total, data.size() - total);
        if (n <= 0 && errno != EINTR) throw std::runtime_error("Ошибка при отправке данных.");
        total += n;
    }
    LOG(INFO) << "Клиент отправил сообщение размера " << data.size();
}