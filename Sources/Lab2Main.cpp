#include <iostream>
#include <fstream>
#include "NMAC256.hpp"
#include "HMAC.hpp"
#include "SimpleMAC.hpp"
#include "KDF_R_13235651022.hpp"
#include "Utils.hpp"

INITIALIZE_EASYLOGGINGPP

enum class InnerMACVariants { NMAC = 0, HMAC = 1, Simple = 2 };
enum class OuterMACVariants { NMAC = 0, HMAC256 = 1, HMAC512 = 2, CMAC = 3 };

struct Params {
    std::string key_file = "";
    std::string text_file = "";
    std::string out_file = "";
    std::string mac_file = "";
    InnerMACVariants first_stage_variant = InnerMACVariants::NMAC;
    OuterMACVariants second_stage_variant = OuterMACVariants::CMAC;
    uint8_t user_info[16] = {0x00};
    uint8_t additional_info[16] = {0x00};
};

template <IsMAC OuterMAC>
struct MacParams {
    SecureBuffer<32> key;
    SecureBuffer<32> salt;
    uint8_t IV[OuterMAC::DigestSize];
};

template <IsMAC InnerMAC, IsMAC OuterMAC>
void getMacParams(
    MacParams<OuterMAC> &mac_params,
    const Params &params,
    SecureBuffer<16> &expected_mac
) {
    MasterKeySecureBuffer<32> key;
    getAndCheckKey(params.key_file.c_str(), key);
    std::ifstream mac_params_source;
    if (!params.mac_file.empty()) {
        mac_params_source.open(params.mac_file, std::ios::binary);
        if (!mac_params_source) throw crispex::privilege_error("Не удалось открыть файл с MAC.");
    }
        
    else {
        mac_params_source.open("/dev/urandom", std::ios::binary);
        if (!mac_params_source) throw crispex::lack_of_entropy("Нет доступа к /dev/urandom.");
    }
    mac_params_source.read(reinterpret_cast<char *>(mac_params.salt.raw()), 32);
    if (!mac_params_source) {
        if (params.mac_file.empty()) throw crispex::lack_of_entropy("Ошибка получения соли.");
        else throw crispex::file_format_error("Ошибка получения соли.");
    }
    mac_params_source.read(
        reinterpret_cast<char *>(mac_params.IV),
        OuterMAC::DigestSize
    );
    if (!mac_params_source) {
        if (params.mac_file.empty()) throw crispex::lack_of_entropy("Ошибка получения инициализирующего вектора.");
        else throw crispex::file_format_error("Ошибка получения инициализирующего вектора.");
    }
    if (!params.mac_file.empty()) {
        mac_params_source.read(reinterpret_cast<char *>(expected_mac.raw()),16);
        if (!mac_params_source) throw crispex::file_format_error("Ошибка получения ожидаемого MAC.");
    }
    mac_params_source.close();
    KDF_R_13235651022<InnerMAC, OuterMAC, 32> kdf(key, mac_params.salt);
    static constexpr uint8_t application_info[] = {
        'D','i','g','e','s','t',' ','k','e','y',' ','f','o','r',' ',
        'K','u','z','n','e','c','h','i','k','-','O','M','A','C','.','.','.'
    };
    kdf.fetch(
        mac_params.key.raw(), 32, mac_params.IV,
        application_info,
        params.user_info, params.additional_info
    );
}

static void printHelp(const char* progName) noexcept {
    std::cout << "Использование: " << progName << " [опции]\n\n"
        "Обязательные параметры:\n"
        "  -k <файл>       Файл с ключом\n"
        "  -i <файл>       Файл с входными данными\n"
        "  -o <файл>       Файл для записи MAC (если вычисляем MAC)\n"
        "  -m <файл>       Файл с MAC для проверки (если проверяем)\n"
        "\n"
        "Дополнительные параметры:\n"
        "  -f <вариант>    Первый этап: NMAC | HMAC | Simple (по умолчанию: NMAC)\n"
        "  -s <вариант>    Второй этап: NMAC | HMAC256 | HMAC512 | CMAC (по умолчанию: CMAC)\n"
        "  -u <строка>     Информация о пользователе (до 16 байт: обрезается при превышении,\n"
        "                 дополняется нулями при недостатке, по умолчанию все байты — 0)\n"
        "  -a <строка>     Доп. информация (до 16 байт: обрезается при превышении,\n"
        "                 дополняется нулями при недостатке, по умолчанию все байты — 0)\n"
        "  -h              Показать эту справку и выйти\n"
        "\n"
        "Примеры:\n"
        "  " << progName << " -k key.bin -i input.txt -o mac.bin\n"
        "  " << progName << " -k key.bin -i input.txt -m mac.bin -f HMAC -s CMAC -u user -a extra\n"
        << std::endl;
}


static int getParams(Params &params, int argc, char **argv) noexcept {
    int opt;
    while ((opt = getopt(argc, argv, "k:i:o:m:f:s:u:a:h")) != -1)
        switch (opt) {
            case 'k': {
                params.key_file = std::string(optarg);
                break;
            }
            case 'i': {
                params.text_file = std::string(optarg);
                break;
            }
            case 'o': {
                params.out_file = std::string(optarg);
                break;
            }
            case 'm': {
                params.mac_file = std::string(optarg);
                break;
            }
            case 'f': {
                std::string first_stage_string(optarg);
                if (first_stage_string == "NMAC")
                    params.first_stage_variant = InnerMACVariants::NMAC;
                else if (first_stage_string == "HMAC")
                    params.first_stage_variant = InnerMACVariants::HMAC;
                else if (first_stage_string == "Simple")
                    params.first_stage_variant = InnerMACVariants::Simple;
                else {
                    std::cerr << "Ошибка: неизвестный вариант первого этапа." << std::endl;
                    printHelp(argv[0]);
                    return -1;
                }
                break;
            }
            case 's': {
                std::string second_stage_string(optarg);
                if (second_stage_string == "NMAC")
                    params.second_stage_variant = OuterMACVariants::NMAC;
                else if (second_stage_string == "HMAC256")
                    params.second_stage_variant = OuterMACVariants::HMAC256;
                else if (second_stage_string == "HMAC512")
                    params.second_stage_variant = OuterMACVariants::HMAC512;
                else if (second_stage_string == "CMAC")
                    params.second_stage_variant = OuterMACVariants::CMAC;
                else {
                    std::cerr << "Ошибка: неизвестный вариант второго этапа." << std::endl;
                    printHelp(argv[0]);
                    return -1;
                }
                break;
            }
            case 'u': {
                size_t to_copy = std::min(strlen(optarg), static_cast<size_t>(16));
                memcpy(params.user_info, optarg, to_copy);
                break;
            }
            case 'a': {
                size_t to_copy = std::min(strlen(optarg), static_cast<size_t>(16));
                memcpy(params.additional_info, optarg, to_copy);
                break;
            }
            case 'h': {
                printHelp(argv[0]);
                return -2;
            }
            default: {
                std::cerr << "Ошибка: некорректный аргумент." << std::endl;
                printHelp(argv[0]);
                return -3;
            }
        }
    if (params.key_file.empty()) {
        std::cerr << "Ошибка: не указан файл с ключом (-k)." << std::endl;
        printHelp(argv[0]);
        return -4;
    }
    if (params.text_file.empty()) {
        std::cerr << "Ошибка: не указан файл с данными (-i)." << std::endl;
        printHelp(argv[0]);
        return -5;
    }
    if (params.out_file.empty() && params.mac_file.empty()) {
        std::cerr << "Ошибка: необходимо указать -o (файл MAC) или -m (MAC для проверки)." << std::endl;
        printHelp(argv[0]);
        return -6;
    }
    if (!params.out_file.empty() && !params.mac_file.empty()) {
        std::cerr
            << "Ошибка: нельзя указать параметры -o (файл MAC) и -m (MAC для проверки) одновременно."
            << std::endl;
        printHelp(argv[0]);
        return -7;
    }
    return 0;
}

template <IsMAC OuterMAC>
void initKuznechikOMACCTXFromKDF(
        OMAC<Kuznechik> &ctx, const Params &params,
        std::ofstream &out_file,
        SecureBuffer<16> &expected_mac
) {
    MacParams<OuterMAC> mac_params;
    switch (params.first_stage_variant) {
        case InnerMACVariants::NMAC: {
            getMacParams<NMAC256<32>, OuterMAC>(mac_params, params, expected_mac);
            break;
        }
        case InnerMACVariants::HMAC: {
            getMacParams<HMAC<Streebog512, 32>, OuterMAC>(mac_params, params, expected_mac);
            break;
        }
        case InnerMACVariants::Simple: {
            getMacParams<SimpleMAC<32>, OuterMAC>(mac_params, params, expected_mac);
            break;
        }
        default:
            break;
    }
    if (out_file.is_open()) {
        out_file.write(reinterpret_cast<char *>(mac_params.salt.raw()), 32);
        if (!out_file) throw crispex::privilege_error("Не удалось записать соль в выходной файл.");
        out_file.write(reinterpret_cast<char *>(mac_params.IV), OuterMAC::DigestSize);
        if (!out_file) throw crispex::privilege_error("Не удалось записать инициализирующий вектор в выходной файл.");
    }
    ctx.initKeySchedule(mac_params.key);
}

template <IsMAC OuterMAC>
int getOrCheckFileMac(const Params &params) {
    OMAC<Kuznechik> ctx;
    std::ofstream out_file;
    if (!params.out_file.empty()) {
        out_file.open(params.out_file, std::ios::binary);
        if (!out_file) throw crispex::privilege_error("Не удалось открыть файл для записи результата.");
    }
    SecureBuffer<16> expected_mac;
    initKuznechikOMACCTXFromKDF<OuterMAC>(ctx, params, out_file, expected_mac);
    std::ifstream file(params.text_file, std::ios::binary);
    if (!file) throw crispex::privilege_error("Не удалось открыть файл с текстом.");
    std::vector<uint8_t> buf;
    while (fillBuffer(file, buf))
        ctx.update(buf);
    ctx.update(buf);
    SecureBuffer<16> mac;
    ctx.digest(mac.raw());
    if (out_file.is_open()) {
        out_file.write(reinterpret_cast<char *>(mac.raw()), 16);
        if (!out_file) throw crispex::privilege_error("Не удалось записать MAC в выходной файл.");
        std::cout << "WRITTEN" << std::endl;
        return 0;
    } else if (expected_mac == mac) {
        std::cout << "OK" << std::endl;
        return 0;
    }
    std::cout << "FAIL" << std::endl;
    return 1;
}

int main(int argc, char **argv) {
    confLog(false, true, "lab.log");
    Params params;
    if (getParams(params, argc, argv))
        return -1;
    int rc = 0;
    try {
        switch (params.second_stage_variant) {
            case OuterMACVariants::NMAC: {
                rc = getOrCheckFileMac<NMAC256<32>>(params);
                break;
            }
            case OuterMACVariants::HMAC256: {
                rc = getOrCheckFileMac<HMAC<Streebog256, 32>>(params);
                break;
            }
            case OuterMACVariants::HMAC512: {
                rc = getOrCheckFileMac<HMAC<Streebog512, 32>>(params);
                break;
            }
            case OuterMACVariants::CMAC: {
                rc = getOrCheckFileMac<OMAC<Kuznechik>>(params);
                break;
            }
            default:
                break;
        }
    } catch (std::exception &e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return -2;
    }
    return rc;
}