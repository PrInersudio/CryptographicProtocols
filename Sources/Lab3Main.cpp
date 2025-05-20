#include <unistd.h>
#include <iostream>
#include <iomanip>
#include "Kuznechik.hpp"
#include "CTR_DRBG.hpp"

#define BUFFER_SIZE 8192
#define BAR_WIDTH 50

struct Params {
    std::string out_file = "";
    size_t num = 0;
};

static void printHelp(const char* progName) noexcept {
    std::cout << "Использование: " << progName << " -o <файл> -n <размер>\n"
              << "Параметры:\n"
              << "  -o <файл>     Указать путь к выходному файлу\n"
              << "  -n <размер>   Количество генерируемых байт.\n"
              << "                Можно использовать суффиксы для указания единиц измерения:\n"
              << "                  K - килобайты (1024 байт)\n"
              << "                  M - мегабайты (1024 * 1024 байт)\n"
              << "                  G - гигабайты (1024 * 1024 * 1024 байт)\n"
              << "                Можно указывать дробные значения, например 1.5M.\n"
              << "                В этом случае значение будет округлено вниз до ближайшего целого байта.\n"
              << "                Примеры:\n"
              << "                  -n 1024     (1024 байта)\n"
              << "                  -n 10K      (10 килобайт)\n"
              << "                  -n 5.5M     (5.5 мегабайт)\n"
              << "  -h            Показать эту справку\n"
              << std::endl;
}

size_t parseNum(const std::string &str) {
    size_t num_end = 0;
    while (num_end < str.size() && (std::isdigit(str[num_end]) || str[num_end] == '.'))
        ++num_end;
    if (num_end == 0) throw std::invalid_argument("Нет числа в параметре.");
    double number = std::stod(str.substr(0, num_end));
    std::string unit = str.substr(num_end);
    for (char &c : unit) c = static_cast<char>(std::toupper(c));
    if (unit.empty()) return static_cast<size_t>(number);
    else if (unit == "K") return static_cast<size_t>(number * 1024);
    else if (unit == "M") return static_cast<size_t>(number * 1024 * 1024);
    else if (unit == "G") return static_cast<size_t>(number * 1024 * 1024 * 1024);
    else throw std::invalid_argument("Неизвестный суффикс единицы измерения");
}

static int getParams(Params &params, int argc, char **argv) noexcept {
    int opt;
    while ((opt = getopt(argc, argv, "o:n:h")) != -1)
        switch (opt) {
            case 'o': {
                params.out_file = std::string(optarg);
                break;
            }
            case 'n': {
                try {
                    params.num = parseNum(optarg);
                } catch (const std::invalid_argument &e) {
                    std::cerr
                        << "Ошибка. Некорректный аргумент количества генерируемых байт (-n): "
                        << e.what() << std::endl;
                    printHelp(argv[0]);
                    return -1;
                }
                break;
            }
            case 'h': {
                printHelp(argv[0]);
                return -3;
            }
            default: {
                std::cerr << "Ошибка: некорректный аргумент." << std::endl;
                printHelp(argv[0]);
                return -4;
            }
        }
    if (params.out_file.empty()) {
        std::cerr << "Ошибка: не указан выходной файл (-o)." << std::endl;
        printHelp(argv[0]);
        return -5;
    }
    if (params.num == 0) {
        std::cerr << "Ошибка: не указан аргумент количества генерируемых байт (-n)." << std::endl;
        printHelp(argv[0]);
        return -6;
    }
    return 0;
}

void printProgress(size_t current, size_t total) {
    float progress = static_cast<float>(current) / static_cast<float>(total);
    size_t pos = static_cast<size_t>(BAR_WIDTH * progress);

    std::cout << "\r" << ((progress < 1.0f) ? "\033[33m" : "\033[32m\a") << "[";
    if (pos != 0) {
        for (size_t i = 0; i < pos - 1; ++i)
            std::cout << "=";
        if (pos != BAR_WIDTH) std::cout << ">"; else std::cout << "=";
    }
    for (size_t i = pos; i < BAR_WIDTH; ++i)
        std::cout << " ";
    std::cout << "] \033[1m" << std::fixed << std::setprecision(2) << (progress * 100.0f) << "%\033[0m";
    std::cout.flush();
}

int main(int argc, char **argv) {
    Params params;
    if (getParams(params, argc, argv)) return -1;
    try {
        std::ofstream out_file(params.out_file, std::ios::binary);
        if (!out_file) throw std::runtime_error("Не удалось открыть выходной файл.");
        CTR_DRBG<Kuznechik, true> rng;

        uint8_t buffer[BUFFER_SIZE];
        size_t num_of_blocks = params.num / BUFFER_SIZE;
        size_t remainder = params.num % BUFFER_SIZE;

        for (size_t i = 0; i < num_of_blocks; ++i) {
            rng(buffer, BUFFER_SIZE);
            out_file.write(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
            if (!out_file) throw std::runtime_error("Запись прервана после записи " + std::to_string(i * BUFFER_SIZE) + " байт.");
            printProgress((i + 1) * BUFFER_SIZE, params.num);
        }
        if (remainder > 0) {
            rng(buffer, remainder);
            out_file.write(reinterpret_cast<char *>(buffer), static_cast<std::streamsize>(remainder));
            if (!out_file)
                throw std::runtime_error("Запись прервана после записи "  + std::to_string(num_of_blocks * BUFFER_SIZE) + " байт.");
            printProgress(params.num, params.num);
        }
        std::cout << std::endl;
        std::cout << "Генерация завершена успешно." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return -2;
    }
    return 0;
}