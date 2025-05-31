#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <thread>
#include "TCP.hpp"
#include "CRISPExceptions.hpp"

TCPServer::TCPServer(const uint16_t port) {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0)
        throw crispex::init_connection_error("Не удалось открыть сокет сервера.");
    LOG(INFO) << "Инициализирована структура сокета сервера";
    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    if (bind(sockfd_, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr))) {
        ::close(sockfd_);
        throw crispex::init_connection_error("Не удался bind сокета сервера.");
    }
    LOG(INFO) << "Сервер прикреплён к порту " << port;
    if (listen(sockfd_, 5)) {
        ::close(sockfd_);
        throw crispex::init_connection_error("Сервер не смог начать прослушивание.");
    }
    LOG(INFO) << "Сервер начал прослушивание на порту " << port;
}

void TCPServer::accept(const std::string &client_ip) {
    in_addr clientaddr{};
    if (inet_pton(AF_INET, client_ip.c_str(), &clientaddr) <= 0)
        throw crispex::invalid_argument("Некорректный IP-адрес клиента.");
    struct sockaddr_in cli;
    socklen_t len = sizeof(cli);
    LOG(INFO) << "Ожидание подключения от " << client_ip;
    connfd_ = ::accept(sockfd_, reinterpret_cast<struct sockaddr *>(&cli), &len);
    if (connfd_ < 0) {
        ::close(sockfd_);
        throw crispex::init_connection_error("Не удалось принять соединение.");
    }
    if (cli.sin_addr.s_addr != clientaddr.s_addr) {
        ::close(sockfd_);
        ::close(connfd_);
        throw crispex::compromise_attempt("Попытка подключения с неизвестного ip адреса.");
    }
    LOG(INFO) << "Сервер успешно принял подключение к " << client_ip;
}

std::vector<uint8_t> TCPServer::operator()(const size_t size) const {
    if (size > MAX_RECV_SIZE) throw crispex::invalid_argument("Недопустимый размер сообщения.");
    if (sockfd_ < 0) throw crispex::init_connection_error("Сокет сервера был перемещён из данного объекта.");
    if (connfd_ < 0) throw crispex::init_connection_error("Нет активного соединения для чтения.");
    LOG(INFO) << "Сервер ожидает сообщение размера " << size;
    std::vector<uint8_t> result(size);
    uint8_t buffer[RECV_BUF_SIZE];
    ssize_t n;
    size_t total = 0;
    std::lock_guard<std::mutex> lock(read_mutex_);
    const int connfd = connfd_;
    while (total < size) {
        errno = 0;
        n = read(connfd, buffer, std::min(RECV_BUF_SIZE, size - total));
        if (n <= 0) {
            if (errno != EINTR)
                throw crispex::socket_closed("Ошибка при получении данных или соедиенение было закрыто.");
            else continue;
        }
        memcpy(result.data() + total, buffer, static_cast<size_t>(n));
        total += static_cast<size_t>(n);
    }
    LOG(INFO) << "Сервер принял сообщение размера " << size;
    return result;
}

void TCPServer::operator()(const std::vector<uint8_t> &data) const {
    if (sockfd_ < 0) throw crispex::init_connection_error("Сокет сервера был перемещён из данного объекта.");
    if (connfd_ < 0) throw crispex::init_connection_error("Нет активного соединения для отправки.");
    if (data.size() > MAX_RECV_SIZE) throw crispex::send_error("Превышен максимальный размер сообщения.");
    LOG(INFO) << "Сервер собирается отправить сообщение размера " << data.size();
    size_t total = 0;
    ssize_t n;
    std::lock_guard<std::mutex> lock(write_mutex_);
    const int connfd = connfd_;
    while (total < data.size()) {
        n = write(connfd, data.data() + total, data.size() - total);
        if (n <= 0  && errno != EINTR) throw crispex::socket_closed("Ошибка при отправке данных или соедиенение было закрыто.");
        total += static_cast<size_t>(n);
    }
    LOG(INFO) << "Сервер отправил сообщение размера " << data.size();
}

TCPClient::TCPClient() {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0)
        throw crispex::init_connection_error("Не удалось открыть сокет клиента.");
    LOG(INFO) << "Инициализирована структура сокета клиента";
}

void TCPClient::connect(const std::string &server_ip, const uint16_t server_port) const {
    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip.c_str(), &servaddr.sin_addr) <= 0)
        throw crispex::invalid_argument("Некорректный IP-адрес сервера.");
    servaddr.sin_port = htons(server_port);
    LOG(INFO) << "Клиент пытается подключиться к " << server_ip;
    size_t retry = 0;
    while (true) {
        if (::connect(sockfd_, reinterpret_cast<struct sockaddr *>(&servaddr), sizeof(servaddr)) == 0) break;
        if (errno != ECONNREFUSED) throw crispex::init_connection_error("Не удалось подключиться к серверу.");
        LOG(INFO) << "Попытка клиента подключиться номер" << (++retry);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    LOG(INFO) << "Клиент успешно подключился к " << server_ip;
}

std::vector<uint8_t> TCPClient::operator()(const size_t size) const {
    if (size > MAX_RECV_SIZE) throw crispex::invalid_argument("Недопустимый размер сообщения.");
    if (sockfd_ < 0) throw crispex::init_connection_error("Сокет был перемещён из данного объекта.");
    std::vector<uint8_t> result(size);
    uint8_t buffer[RECV_BUF_SIZE];
    ssize_t n;
    size_t total = 0;
    LOG(INFO) << "Клиент ожидает сообщение размера " << size;
    std::lock_guard<std::mutex> lock(read_mutex_);
    const int sockfd = sockfd_;
    while (total < size) {
        n = read(sockfd, buffer, std::min(RECV_BUF_SIZE, size - total));
        if (n <= 0) {
            if (errno != EINTR)
                throw crispex::socket_closed("Ошибка при получении данных или соедиенение было закрыто.");
            else continue;
        }
        memcpy(result.data() + total, buffer, static_cast<size_t>(n));
        total += static_cast<size_t>(n);
    }
    LOG(INFO) << "Клиент принял сообщение размера " << size;
    return result;
}

void TCPClient::operator()(const std::vector<uint8_t> &data) const {
    if (sockfd_ < 0) throw crispex::init_connection_error("Сокет был перемещён из данного объекта.");
    if (data.size() > MAX_RECV_SIZE) throw crispex::invalid_argument("Превышен максимальный размер сообщения.");
    LOG(INFO) << "Клиент собирается отправить сообщение размера " << data.size();
    size_t total = 0;
    ssize_t n;
    std::lock_guard<std::mutex> lock(write_mutex_);
    const int sockfd = sockfd_;
    while (total < data.size()) {
        errno = 0;
        n = write(sockfd, data.data() + total, data.size() - total);
        if (n <= 0 && errno != EINTR) throw crispex::socket_closed("Ошибка при отправке данных или соедиенение было закрыто.");
        total += static_cast<size_t>(n);
    }
    LOG(INFO) << "Клиент отправил сообщение размера " << data.size();
}