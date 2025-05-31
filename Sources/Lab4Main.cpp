#include <ncurses.h>
#include <future>
#include "CRISPMessenger.hpp"
#include "utf8.h"

INITIALIZE_EASYLOGGINGPP

struct Params {
    std::string key_file = "";
    CryptographicSuites::ID cryptographic_suites = CryptographicSuites::ID::KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC;
    std::string file_directory = "received_files";
    uint8_t local_user_info[16] = {0x00};
    uint8_t remote_user_info[16] = {0x00};
    uint16_t local_port = 0;
    std::string remote_ip = "";
    uint16_t remote_port = 0;
};


static void printHelp(const std::string& execName) {
    std::cout << "Использование: " << execName << " [опции]\n"
              << "Опции:\n"
              << "  -k <путь>         Путь к файлу мастер-ключа (обязательно)\n"
              << "  -c <набор>        Название криптографического набора (по умолчанию: KuznechikCTR_KuznechikCMAC_256_128_R13235651022_NMAC_CMAC)\n"
              << "  -d <путь>         Директория для сохранения полученных файлов (по умолчанию: received_files)\n"
              << "  -u <16 байт>      Имя пользователя (будет обрезано до 16 байт)\n"
              << "  -r <16 байт>      Имя получателя (будет обрезано до 16 байт)\n"
              << "  -h                Показать эту справку и выйти\n"
              << "  -l                Показать список доступных криптографических наборов и выйти\n"
              << "  -p <порт>         Локальный порт для запуска серверного сокета\n"
              << "  -a <ip:порт>      Адрес получателя в формате ip:порт\n"
              << "\n"
              << "Пример:\n"
              << "  " << execName << " -k master.key -c KuznechikCTR_KuznechikCMAC_256_128_R13235651022_HMAC_HMAC256 -u Alice -r Bob\n"
              << std::endl;
}

static void printAvailableSuites() {
    std::cout << "Доступные криптографические наборы:\n";
    for (const auto& pair : CryptographicSuites::getAllSuites()) {
        std::cout << "  " << pair.first << '\n';
    }
    std::cout << std::endl;
}

static void getParams(Params &params, int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "k:c:d:u:r:hlp:a:")) != -1) {
        switch (opt) {
            case 'k': {
                params.key_file = std::string(optarg);
                break;
            }
            case 'c': {
                params.cryptographic_suites = CryptographicSuites::from_string(optarg);
                break;
            }
            case 'd': {
                params.file_directory = std::string(optarg);
                break;
            }
            case 'u': {
                memcpy(params.local_user_info, optarg, std::min(strlen(optarg), size_t(16)));
                break;
            }
            case 'r': {
                memcpy(params.remote_user_info, optarg, std::min(strlen(optarg), size_t(16)));
                break;
            }
            case 'h': {
                printHelp(argv[0]);
                throw crispex::help_param("Вызван help.");
            }
            case 'l': {
                printAvailableSuites();
                throw crispex::help_param("Вызван список наборов.");
            }
            case 'p': {
                params.local_port = static_cast<uint16_t>(std::strtoul(optarg, NULL, 10));
                break;
            }
            case 'a': {
                std::string addr(optarg);
                const size_t colon_idx = addr.find(':');
                if (colon_idx == std::string::npos) {
                    std::cerr << "Адрес (-p) должен быть в формате ip:порт." << std::endl;
                    printHelp(argv[0]);
                    throw crispex::help_param("Некорректный формат адреса");
                }
                params.remote_ip = addr.substr(0, colon_idx);
                params.remote_port = static_cast<uint16_t>(std::strtoul(addr.substr(colon_idx + 1).c_str(), NULL, 10));
                break;
            }
            default: {
                std::cerr << "Несуществующий аргумент " << static_cast<char>(opt) << " ." << std::endl;
                printHelp(argv[0]);
                throw crispex::help_param("Несуществующий аргумент " + std::to_string(static_cast<char>(opt)) + " .");
                return;
            }
        }
    }
    if (params.key_file.empty()) {
        std::cerr << "Не введён файл мастер-ключа (-k)." << std::endl;
        printHelp(argv[0]);
        throw crispex::invalid_argument("Не введён файл мастер-ключа.");
    } else if (params.local_user_info[0] == 0x00) {
        std::cerr << "Не введёно имя локального пользователя (-u)." << std::endl;
        printHelp(argv[0]);
        throw crispex::invalid_argument("Не введёно имя локального пользователя.");
    } else if (params.remote_user_info[0] == 0x00) {
        std::cerr << "Не введёно имя пользователя-получателя (-r)." << std::endl;
        printHelp(argv[0]);
        throw crispex::invalid_argument("Не введёно имя пользователя-получателя.");
    } else if (params.local_port == 0) {
        std::cerr << "Не задан локальный порт (-p)." << std::endl;
        printHelp(argv[0]);
        throw crispex::invalid_argument("Не задан локальный порт.");
    } else if (params.remote_ip.empty() || params.remote_port == 0) {
        std::cerr << "Не задан адрес получателя (-a)." << std::endl;
        printHelp(argv[0]);
        throw crispex::invalid_argument("Не задан адрес получателя.");
    }
}

std::vector<std::pair<std::string, bool>> history;
std::wstring current_input;
std::mutex io_mutex;
std::atomic_bool running = true;
std::shared_ptr<CRISPMessenger> messenger = nullptr;
enum {
    COLOR_MINE = 1,
    COLOR_THEIRS = 2,
    COLOR_INPUT = 3
};

inline static void init_colors() noexcept {
    start_color();
    use_default_colors();
    init_pair(COLOR_MINE, COLOR_GREEN, -1);
    init_pair(COLOR_THEIRS, COLOR_CYAN, -1);
    init_pair(COLOR_INPUT, COLOR_YELLOW, -1);
}

static std::vector<std::string> wrapUtf8(const std::string& msg, size_t max_width) {
    std::vector<std::string> lines;
    auto it = msg.begin();
    while (it != msg.end()) {
        auto line_start = it;
        size_t width = 0;
        while (it != msg.end() && width < max_width) {
            auto temp = it;
            utf8::next(temp, msg.end());
            ++width;
            it = temp;
        }
        lines.emplace_back(line_start, it);
    }
    return lines;
}

std::wstring utf8ToWstring(const std::string& str) {
    std::wstring result;
    auto it = str.begin();
    auto end = str.end();
    while (it != end) {
        uint32_t cp = utf8::next(it, end);
        result.push_back(static_cast<wchar_t>(cp));
    }
    return result;
}

std::string utf8FromWstring(const std::wstring& wstr) {
    std::string result;
    result.reserve(wstr.size() * 4);
    for (wchar_t wc : wstr) {
        uint32_t cp = static_cast<uint32_t>(wc);
        char utf8buf[4];
        char* end = utf8::utf32to8(&cp, &cp + 1, utf8buf);
        result.append(utf8buf, end);
    }
    return result;
}

static void redraw() {
    std::lock_guard<std::mutex> lock(io_mutex);
    clear();
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    size_t max_lines = static_cast<size_t>(rows) - 2;
    std::vector<std::string> visual_lines;
    for (const auto& [msg, mine] : history) {
        std::vector<std::string> lines = wrapUtf8(msg, static_cast<size_t>(cols) - 4);
        for (auto& line : lines) {
            visual_lines.emplace_back((mine ? '\x1' : '\x0') + line);
        }
    }
    size_t start = visual_lines.size() > max_lines ? visual_lines.size() - max_lines : 0;
    for (size_t i = start; i < visual_lines.size(); ++i) {
        bool mine = visual_lines[i][0] == '\x1';
        std::string line = visual_lines[i].substr(1);
        attron(COLOR_PAIR(mine ? COLOR_MINE : COLOR_THEIRS));

        std::wstring wline = utf8ToWstring(line);
        int utf8_len = static_cast<int>(wline.size());
        int x = mine ? std::max(0, cols - utf8_len - 2) : 2;

        mvaddwstr(static_cast<int>(i - start), x, wline.c_str());

        attroff(COLOR_PAIR(mine ? COLOR_MINE : COLOR_THEIRS));
    }
    attron(COLOR_PAIR(COLOR_INPUT));
    mvaddwstr(rows - 1, 0, L"> ");
    mvaddwstr(rows - 1, 2, current_input.c_str());
    attroff(COLOR_PAIR(COLOR_INPUT));
    move(rows - 1, 2 + static_cast<int>(current_input.size()));
    refresh();
}


static void recvThread(std::promise<std::exception_ptr> &accept_result) {
    while(running.load()) try {
        std::string msg = messenger->recv();
        LOG(INFO) << "Получено сообщение: " << msg;
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            history.emplace_back(msg, false);
        }
        redraw();
    } catch (const crispex::recv_error &e) {
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            history.emplace_back("***Ошибка при получении сообщения.***", false);
        }
        redraw();
        LOG(WARNING) << e.what();
    } catch(const crispex::privilege_error &e) {
        {
            std::lock_guard<std::mutex> lock(io_mutex);
            history.emplace_back("***Ошибка при сохранении файла.***", false);
        }
        redraw();
        LOG(WARNING) << e.what();
    } catch (const crispex::socket_closed &e) {
        LOG(INFO) << "ВЫход из recvThread";
        accept_result.set_value(nullptr);
        return;
    } catch (...) {
        LOG(INFO) << "ВЫход из recvThread";
        accept_result.set_value(std::current_exception());
        running.store(false);
        return;
    }
    LOG(INFO) << "ВЫход из recvThread";
    accept_result.set_value(nullptr);
}

static void sendThread(std::promise<std::exception_ptr> &accept_result) {
    wint_t wch;
    while (running.load()) {
        int res = wget_wch(stdscr, &wch);
        if (res == ERR) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (wch == KEY_BACKSPACE || wch == 127 || wch == 8) {
            std::lock_guard<std::mutex> lock(io_mutex);
            if (!current_input.empty()) {
                current_input.pop_back();
            }
        } else if (wch == L'\n' || wch == L'\r') {
            std::wstring input;
            {
                std::lock_guard<std::mutex> lock(io_mutex);
                input = std::move(current_input);
                current_input.clear();
            }
            std::string input_utf8 = utf8FromWstring(input);
            if (!input_utf8.empty()) {
                try {
                    if (input_utf8.rfind("/file ", 0) == 0) {
                        std::string filename = input_utf8.substr(6);
                        LOG(INFO) << "Будет отправлен файл с именем " << filename;
                        messenger->send(filename, true);
                        std::lock_guard<std::mutex> lock(io_mutex);
                        history.emplace_back("[Файл отправлен: " + filename + "]", true);
                    } else {
                        LOG(INFO) << "Будет отправлено сообщение " << input_utf8;
                        messenger->send(input_utf8, false);
                        std::lock_guard<std::mutex> lock(io_mutex);
                        history.emplace_back(input_utf8, true);
                    }
                } catch (const crispex::send_error &e) {
                    std::lock_guard<std::mutex> lock(io_mutex);
                    history.emplace_back("***Ошибка при отправке***", true);
                    LOG(WARNING) << e.what();
                } catch(const crispex::privilege_error &e) {
                    std::lock_guard<std::mutex> lock(io_mutex);
                    history.emplace_back("***Ошибка при чтении файла.***", false);
                    redraw();
                    LOG(WARNING) << e.what();
                } catch (const crispex::socket_closed &e) {
                    LOG(INFO) << "ВЫход из sendThread";
                    accept_result.set_value(nullptr);
                    return;
                } catch (...) {
                    LOG(INFO) << "ВЫход из sendThread";
                    accept_result.set_value(std::current_exception());
                    running.store(false);
                    return;
                }
            }
        } else if (iswprint(wch)) {
            std::lock_guard<std::mutex> lock(io_mutex);
            current_input.push_back(static_cast<wchar_t>(wch));
        }
        redraw();
    }
    LOG(INFO) << "ВЫход из sendThread";
    accept_result.set_value(nullptr);
}


void handle_sigint(int) {
    running.store(false);
    if (messenger) messenger->close();
    ungetch(ERR);
}

inline void ncursesSetup() noexcept {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(1);
    init_colors();
}

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    std::signal(SIGINT, handle_sigint);
    confLog(false, true, "lab.log");
    Params params;
    LOG(INFO) << "Считывание параметров командной строки";
    try { getParams(params, argc, argv); }
    catch (const std::exception &e) {
        LOG(ERROR) << e.what();
        return -1;
    }
    LOG(INFO) << "Параметры успешно считаны";
    try {
        messenger = std::make_shared<CRISPMessenger>(
            params.local_port, params.remote_ip, params.remote_port,
            params.cryptographic_suites, params.key_file, params.local_user_info,
            params.remote_user_info, params.file_directory
        );
        ncursesSetup();
        redraw();
        std::promise<std::exception_ptr> recv_result, send_result;
        std::future<std::exception_ptr> recv_future = recv_result.get_future();
        std::future<std::exception_ptr> send_future = send_result.get_future();
        std::thread recvT(recvThread, std::ref(recv_result));
        sendThread(send_result);
        LOG(INFO) << "Вернулся в main из sendThread";
        recvT.join();
        LOG(INFO) << "Join в main с recvThread";
        std::exception_ptr recv_ex = recv_future.get();
        if (recv_ex) std::rethrow_exception(recv_ex);
        LOG(INFO) << "Обработал исключения sendThread";
        std::exception_ptr send_ex = send_future.get();
        if (send_ex) std::rethrow_exception(send_ex);
        LOG(INFO) << "Обработал исключения recvThread";
        endwin();
        LOG(INFO) << "Завершение работы";
        std::cout << "Завершение работы..." << std::endl; 
    } catch (const crispex::compromise_attempt &e) {
        running.store(false);
        endwin();
        LOG(ERROR) << e.what();
        std::cerr << "Обнаружена попытка компроментации. Выполняется блокировка СКЗИ." << std::endl;
        return -2;
    } catch (const crispex::lack_of_entropy &e) {
        running.store(false);
        endwin();
        LOG(ERROR) << e.what();
        std::cerr << "Достигнут теоретический предел криптопримитивов. Выполняется блокировка СКЗИ." << std::endl;
        return -3;
    } catch (const crispex::file_format_error &e) {
        running.store(false);
        endwin();
        LOG(ERROR) << e.what();
        std::cerr << "Неправильный формат файла мастер-ключа." << std::endl;
        return -4;
    } catch (const crispex::init_connection_error &e) {
        running.store(false);
        endwin();
        LOG(ERROR) << e.what();
        std::cerr << "Ошибка подключения." << std::endl;
        return -5;
    } catch(const crispex::privilege_error &e) {
        running.store(false);
        endwin();
        LOG(ERROR) << e.what();
        std::cerr << "Ошибка при чтении ключевого файла." << std::endl;
        return -7;
    } catch (const std::exception &e) {
        running.store(false);
        endwin();
        LOG(ERROR) << e.what();
        std::cerr << "Фатальная ошибка. Обратитесь к администратору." << std::endl;
        return -6;
    } 
    return 0;
}