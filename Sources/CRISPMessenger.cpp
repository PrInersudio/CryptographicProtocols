#include <set>
#include <future>
#include "CRISPMessenger.hpp"
#include "CTR.hpp"

CRISPMessenger::CRISPMessenger(
    const uint16_t local_port,
    const std::string &remote_ip,
    const uint16_t remote_port,
    const CryptographicSuites server_cryptographic_suite,
    const char *key_file,
    const uint8_t (&local_user_info)[16],
    const uint8_t (&remote_user_info)[16],
    const char *file_directory
) : server_(local_port),
    server_cryptographic_suite_(server_cryptographic_suite),
    rng(rng_personalization_string, sizeof(rng_personalization_string)),
    client_seq_num_(rng.uint64()),
    directory_(file_directory),
    max_payload_size_(CRISPMessage::MaxSize - CRISPMessage::precalcSizeWithoutPayload(0, server_cryptographic_suite_))
{
    memcpy(local_user_info_, local_user_info, 16);
    memcpy(remote_user_info_, remote_user_info, 16);
    std::promise<std::exception_ptr> accept_result;
    std::future<std::exception_ptr> accept_future = accept_result.get_future();
    std::thread accept_thread([&] {
        try {
            server_.accept(remote_ip);
            accept_result.set_value(nullptr);
        } catch (...) {
            accept_result.set_value(std::current_exception());
        }
    });
    client_.connect(remote_ip, remote_port);
    accept_thread.join();
    if (std::exception_ptr ex = accept_future.get())
        std::rethrow_exception(ex);

    static const std::vector<uint8_t> error{'E', 'R', 'R', 'O', 'R'};
    static constexpr uint8_t rng_additional_info[] = {
        'C', 'R', 'I', 'S', 'P', 'M', 'e', 's',
        's', 'e', 'n', 'g', 'e', 'r', ' ', 'c',
        'o', 'n', 's', 't', 'r', 'u', 'c', 't',
        'o', 'r', 't', 'e', 's', 't', ' ', 'm',
        'e', 's', 's', 'a', 'g', 'e', '.'
    };
    try {
        getAndCheckKey(key_file, master_key_);
    } catch(...) {
        sendMessage(client_, {++client_seq_num_, error});
        std::rethrow_exception(std::current_exception());
    }

    std::vector<uint8_t> local_ready(16);
    rng(local_ready.data(), local_ready.size());
    sendMessage(client_, {++client_seq_num_, local_ready});
    MessageParts remote_ready = getMessage(server_);
    sendMessage(server_, {++remote_ready.seq_num, remote_ready.part});
    MessageParts local_ready_response = getMessage(client_);
    if (local_ready_response.part == error) throw std::runtime_error("Второй участник отказался от общения.");
    else if (local_ready_response.part != local_ready) throw std::runtime_error(
        "Неккорректное содержание пробного сообшения от второго участника."
        "Либо нелегальный второй участник. Либо нарушена целостность криптографических примитивов."
    );
}

std::vector<uint8_t> CRISPMessenger::encryptKuznechikCTR(const uint64_t seq_num, const std::vector<uint8_t> &data, const SecureBuffer<32> &key) noexcept {
    const Kuznechik cipher(key);
    std::vector<uint8_t> payload = data;
    uint8_t IV[16];
    uint64_t temp = seq_num;
    for (uint8_t i = 0; i < 16; ++i) {
        IV[15 - i] = static_cast<uint8_t>(temp);
        temp >>= 8;
    }
    CTREncrypt<16, 32>(cipher, payload.data(), payload.size(), IV);
    return payload;
}

CRISPMessenger::MessageParts CRISPMessenger::getMessage(const TCP &tcp) const {
    std::vector<uint8_t> size_bytes = tcp(2);
    uint16_t size = (static_cast<uint16_t>(size_bytes[0]) << 8) | size_bytes[1];
    if (size > CRISPMessage::MaxSize)
        throw std::runtime_error("Получен некорректный размер сообщения.");
    CRISPMessage message(tcp(size));
    switch (message.cryptographicSuite()) {
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, NMAC256<32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, HMAC<Streebog256, 32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, HMAC<Streebog512, 32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, OMAC<Kuznechik>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, NMAC256<32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, HMAC<Streebog256, 32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, HMAC<Streebog512, 32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, OMAC<Kuznechik>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, NMAC256<32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, HMAC<Streebog256, 32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, HMAC<Streebog512, 32>>(message, remote_user_info_)};
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
            return {message.seqNum(), handleNULL_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, OMAC<Kuznechik>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, NMAC256<32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, HMAC<Streebog256, 32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, HMAC<Streebog512, 32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<NMAC256<32>, OMAC<Kuznechik>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, NMAC256<32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, HMAC<Streebog256, 32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, HMAC<Streebog512, 32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<HMAC<Streebog512, 32>, OMAC<Kuznechik>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, NMAC256<32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, HMAC<Streebog256, 32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, HMAC<Streebog512, 32>>(message, remote_user_info_)};
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
            return {message.seqNum(), handleKuznechikCTR_KuznechikCMAC_256_128_R13235651022<SimpleMAC<32>, OMAC<Kuznechik>>(message, remote_user_info_)};
        default:
            throw std::invalid_argument("Данный криптографический набор не поддерживается.");
            break;
    }
}

std::string CRISPMessenger::recv() {
    static constexpr uint8_t rng_additional_info[] = {
        'C', 'R', 'I', 'S', 'P', 'M', 'e', 's',
        's', 'e', 'n', 'g', 'e', 'r', ' ', 'f',
        'i', 'l', 'e', 'n', 'a', 'm', 'e', ' ',
        'r', 'a', 'n', 'd', 'o', 'm', ' ', 'a',
        'd', 'd', '.'
    };

    MessageParts type_size = getMessage(server_);
    if (type_size.part.size() < 12) {
        sendMessage(server_, {type_size.seq_num + 1, {'E', 'R', 'R', 'O', 'R'}});
        throw std::runtime_error("Полученное сообщение о типе и количестве CRISP сообщений меньше ожидаемого.");
    }
    sendMessage(server_, {type_size.seq_num + 1, {'A', 'C', 'C', 'E', 'P', 'T'}});
    uint64_t num_messages = 0;
    for (uint8_t i = 0; i < 8; ++i) {
        num_messages <<= 8;
        num_messages |= type_size[i];
    }
    std::string type =  bytesToString(type_size.part.data() + 8, 4);
    std::string received = "";
    std::unique_ptr<std::ostream> stream;
    if (type == "FILE") {
        std::string filename = sanitizeFilename(bytesToString(type_size.part.data() + 12 , type_size.part.size() - 12));
        uint8_t random_add[16];
        rng(random_add, 16, rng_additional_info, sizeof(rng_additional_info));
        filename = bytesToString(random_add, 16) + filename;
        received =  "Полученый файл сохранён как " + filename;
        stream = std::make_unique<std::ofstream>(directory_ / filename, std::ios::binary);
        if (!static_cast<std::ofstream&>(*stream)) 
            throw std::runtime_error("Не удалось открыть файл для записи: " + (directory_ / filename).string());
    }
    else if (type == "TEXT")
        stream = std::make_unique<std::ostringstream>();
    else
        throw std::runtime_error("Получено сообщение неизвестного типа: '" + type + "'.");
    std::set<MessageParts> parts;
    while (parts.size() < num_messages)
        parts.emplace(getMessage(server_));
    for (const MessageParts &part : parts)
        *stream << bytesToString(part.part.data(), part.part.size());
    return received.empty() ? static_cast<std::ostringstream *>(stream.get())->str() : received;
}

CRISPMessenger::MessageFormer CRISPMessenger::chooseMessageFormer() {
    switch (server_cryptographic_suite_) {
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, NMAC256<32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, HMAC<Streebog256, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, HMAC<Streebog512, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, OMAC<Kuznechik>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, NMAC256<32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, HMAC<Streebog256, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, HMAC<Streebog512, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, OMAC<Kuznechik>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, NMAC256<32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, HMAC<Streebog256, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, HMAC<Streebog512, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::NULL_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
            return std::bind(&CRISPMessenger::formNULL_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, OMAC<Kuznechik>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_NMAC:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, NMAC256<32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC256:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, HMAC<Streebog256, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_HMAC512:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, HMAC<Streebog512, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<NMAC256<32>, OMAC<Kuznechik>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_NMAC:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, NMAC256<32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, HMAC<Streebog256, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC512:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, HMAC<Streebog512, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_CMAC:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<HMAC<Streebog512, 32>, OMAC<Kuznechik>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_NMAC:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, NMAC256<32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC256:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, HMAC<Streebog256, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_HMAC512:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, HMAC<Streebog512, 32>>, this, std::placeholders::_1);
        case CryptographicSuites::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_Simple_CMAC:
            return std::bind(&CRISPMessenger::formKuznechikCTR_KuznechikCMAC_256_128_R13235651022CRISPMessage<SimpleMAC<32>, OMAC<Kuznechik>>, this, std::placeholders::_1);
        default:
            throw std::invalid_argument("Данный криптографический набор не поддерживается.");
            break;
    }
}

void CRISPMessenger::send(std::string msg, bool is_file) {
    static const std::vector<uint8_t> accept{'A', 'C', 'C', 'E', 'P', 'T'};

    std::vector<uint8_t> data;
    if (is_file) {
        const size_t filesize = std::filesystem::file_size(msg);
        if (filesize > 2 * 1024 * 1024 * 1024)
            throw std::invalid_argument("Файл больше 2Гб.");
        data.resize(filesize);
        std::ifstream file(msg, std::ios::binary);
        if (!file) throw std::runtime_error("Не удалось открыть файл" + msg + ".");
        file.read(reinterpret_cast<char *>(data.data()), filesize);
        if (!file) throw std::runtime_error("Ощибка при чтении файла " + msg + ".");
    }
    else
        data = std::vector<uint8_t>(msg.begin(), msg.end());
    const size_t num_of_full_payloads = data.size() / max_payload_size_;
    const size_t remainder_payload_size = data.size() % max_payload_size_;
    const size_t num_messages = num_of_full_payloads + (remainder_payload_size == 0 ? 0 : 1);
    uint8_t num_messages_bytes[8];
    size_t temp = num_messages;
    for (uint8_t i = 0; i < 8; ++i) {
        num_messages_bytes[7 - i] = static_cast<uint8_t>(temp & 0xFF);
        temp >>= 8;
    }
    std::vector<uint8_t> size_type;
    size_type.reserve(12 + (is_file ? msg.size() : 0));
    size_type.insert(size_type.end(), num_messages_bytes, num_messages_bytes + 8);
    if (is_file) {
        const std::string type = "FILE";
        size_type.insert(size_type.end(), type.begin(), type.end());
        size_type.insert(size_type.end(), msg.begin(), msg.end());
    }
    else {
        const std::string type = "TEXT";
        size_type.insert(size_type.end(), type.begin(), type.end());
    }
    sendMessage(client_, {++client_seq_num_, size_type});
    MessageParts info_response = getMessage(client_);
    client_seq_num_ += 2;
    if (info_response.part != accept)
        throw std::runtime_error("Второй участник отказался от получения сообщения.");
    for (size_t i = 0; i < num_of_full_payloads; ++i)
        sendMessage(client_, {++client_seq_num_, std::vector<uint8_t>(data.begin() + i * max_payload_size_, data.begin() + (i+1) * max_payload_size_)});
    if (remainder_payload_size > 0)
        sendMessage(client_, {++client_seq_num_, std::vector<uint8_t>(data.end() - remainder_payload_size, data.end())});
}