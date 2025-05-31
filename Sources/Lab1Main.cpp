#include <iostream>
#include <fstream>
#include "OMAC.hpp"
#include "Utils.hpp"

INITIALIZE_EASYLOGGINGPP

int main(int argc, char **argv) {
    confLog(false, true, "lab.log");
    if (argc < 3) {
        std::cout << "Запускать: " << argv[0] << " <файл_ключа> <файл_с_текстом> [ожидаемый MAC в hex]" << std::endl;
        return -1;
    }
    try {
        const std::vector<uint8_t> expected_mac = (argc < 4) ? std::vector<uint8_t>{} : parseHexString(argv[3]); 
        OMAC<Kuznechik> ctx;
        initKuznechikOMACCTX(ctx, argv[1]);
        std::ifstream file(argv[2], std::ios::binary);
        if (!file) throw crispex::privilege_error("Не удалось открыть файл с текстом.");
        std::vector<uint8_t> buf;
        while (fillBuffer(file, buf))
            ctx.update(buf);
        ctx.update(buf);
        const std::vector<uint8_t> mac = ctx.digest(expected_mac.empty() ? 16 : expected_mac.size());
        if (expected_mac.empty()) {
            std::cout << toHexString(mac) << std::endl;
            return 0;
        } else if (expected_mac == mac) {
            std::cout << "OK" << std::endl;
            return 0;
        }
        std::cout << "FAIL" << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return -2;
    }
}