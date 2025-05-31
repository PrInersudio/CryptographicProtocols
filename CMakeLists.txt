cmake_minimum_required(VERSION 3.15...4.0)
project(CryptographicProtocols LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
message(STATUS "Сборка в режиме ${CMAKE_BUILD_TYPE}")

# Отмечаем местонахождение исходных файлов.
set(SOURCES_DIR ${CMAKE_SOURCE_DIR}/Sources)
set(TESTS_SOURCES_DIR ${CMAKE_SOURCE_DIR}/TestsSources)
set(LAB1_TESTS_DATA_DIR ${CMAKE_SOURCE_DIR}/TestsData)
include_directories(${SOURCES_DIR})

# Флаги
set (WARNING_FLAGS
    -Werror
    -pedantic-errors

    -Wall
    -Wextra
    -Wpedantic

    -Wcast-align
    -Wcast-qual
    -Wconversion
    -Wctor-dtor-privacy
    -Wduplicated-branches
    -Wduplicated-cond
    -Wextra-semi
    -Wfloat-equal
    -Wlogical-op
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Woverloaded-virtual
    -Wredundant-decls
    -Wsign-conversion
    -Wsign-promo
)
add_compile_options(${WARNING_FLAGS})
set (GOST_SAFETY_FLAGS
    -fwrapv -fwrapv-pointer
    -fno-strict-aliasing
    -fno-delete-null-pointer-checks
    -D_FORTIFY_SOURCE=2
    -fstack-protector-strong
    -fPIE -fPIC -fpic
    -fno-builtin-fprintf -fno-builtin-fwprintf
    -fno-builtin-printf -fno-builtin-snprintf
    -fno-builtin-sprintf -fno-builtin-swprintf
    -fno-builtin-wprintf
    -fno-builtin-memcpy -fno-builtin-memmove
    -fno-builtin-memset -fno-builtin-strcat
    -fno-builtin-strcpy -fno-builtin-strncat
    -fno-builtin-strncpy -fno-builtin-wcscat
    -fno-builtin-scwcpy -fno-builtin-wcsncat
    -fno-builtin-wcsncpy -fno-builtin-wmemcpy
    -fno-builtin-wmemmove -fno-builtin-wmemset
    -Wclobbered
    -Warray-bounds
    -Wdiv-by-zero
    -Wshift-count-negative -Wshift-count-overflow
    -fpic
    -fstack-protector
)
add_compile_options(${GOST_SAFETY_FLAGS})
add_compile_options(-O3 -fconcepts-diagnostics-depth=2)
add_compile_options(
    $<$<OR:$<CONFIG:Debug>,$<CONFIG:UnitTests>>:-DUNIT_TESTS>
    $<$<CONFIG:Debug>:-fsanitize=address>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:DynamicTests>:-g>
)
add_link_options(
    $<$<CONFIG:Debug>:-fsanitize=address>
    $<$<CONFIG:Release>:-static>
)


if (CMAKE_BUILD_TYPE STREQUAL "DynamicTests")
    add_executable(SecureBufferDynamicTest ${TESTS_SOURCES_DIR}/SecureBufferDynamicTest.cpp)
    return()
endif()

# Сборка модулей.
add_library(Kuznechik OBJECT ${SOURCES_DIR}/Kuznechik.cpp)
add_library(Utils OBJECT ${SOURCES_DIR}/Utils.cpp)
add_library(Streebog OBJECT ${SOURCES_DIR}/Streebog.cpp)
add_library(CRISPMessage OBJECT ${SOURCES_DIR}/CRISPMessage.cpp)
add_library(easylogging OBJECT /usr/include/easylogging++.cc)
target_compile_definitions(easylogging PUBLIC ELPP_NO_DEFAULT_LOG_FILE)
target_compile_options(easylogging PRIVATE -w)
add_library(CRISPMessenger OBJECT ${SOURCES_DIR}/CRISPMessenger.cpp)
add_library(TCP OBJECT ${SOURCES_DIR}/TCP.cpp)

# Сборка программ.
add_executable(lab1 ${SOURCES_DIR}/Lab1Main.cpp)
target_link_libraries(lab1 PRIVATE Kuznechik Utils easylogging)

add_executable(lab2 ${SOURCES_DIR}/Lab2Main.cpp)
target_link_libraries(lab2 PRIVATE Streebog Kuznechik Utils easylogging)

find_package(TBB REQUIRED)

add_executable(lab3 ${SOURCES_DIR}/Lab3Main.cpp)
target_link_libraries(lab3 PRIVATE Kuznechik TBB::tbb easylogging)

find_package(Curses REQUIRED)

add_executable(lab4 ${SOURCES_DIR}/Lab4Main.cpp)
target_link_libraries(lab4 PRIVATE CRISPMessenger CRISPMessage TCP Streebog Kuznechik Utils TBB::tbb easylogging ${CURSES_LIBRARIES})

# Сборка тестов.
if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "UnitTests")

    find_package(GTest REQUIRED)
    enable_testing()
    
    add_executable(SecureBufferTest ${TESTS_SOURCES_DIR}/SecureBufferTest.cpp)
    target_link_libraries(SecureBufferTest PRIVATE GTest::GTest easylogging)
    add_test(NAME SecureBufferTest COMMAND SecureBufferTest)
    set_tests_properties(SecureBufferTest PROPERTIES LABELS "Lab1")
    
    add_executable(KuznechikTest ${TESTS_SOURCES_DIR}/KuznechikTest.cpp)
    target_link_libraries(KuznechikTest PRIVATE Kuznechik GTest::GTest easylogging)
    add_test(NAME KuznechikTest COMMAND KuznechikTest)
    set_tests_properties(KuznechikTest PROPERTIES LABELS "Lab1")

    add_executable(OMACTest ${TESTS_SOURCES_DIR}/OMACTest.cpp)
    target_link_libraries(OMACTest PRIVATE Kuznechik GTest::GTest easylogging)
    add_test(NAME OMACTest COMMAND OMACTest)
    set_tests_properties(OMACTest PROPERTIES LABELS "Lab1")

    add_executable(UtilsTest ${TESTS_SOURCES_DIR}/UtilsTest.cpp)
    target_link_libraries(UtilsTest PRIVATE Utils Kuznechik GTest::GTest easylogging)
    add_test(NAME UtilsTest COMMAND UtilsTest)
    set_tests_properties(UtilsTest PROPERTIES LABELS "Lab1")

    add_executable(StreebogTest ${TESTS_SOURCES_DIR}/StreebogTest.cpp)
    target_link_libraries(StreebogTest PRIVATE Streebog GTest::GTest easylogging)
    add_test(NAME StreebogTest COMMAND StreebogTest)
    set_tests_properties(StreebogTest PROPERTIES LABELS "Lab2")

    add_executable(HMACTest ${TESTS_SOURCES_DIR}/HMACTest.cpp)
    target_link_libraries(HMACTest PRIVATE Streebog GTest::GTest easylogging)
    add_test(NAME HMACTest COMMAND HMACTest)
    set_tests_properties(HMACTest PROPERTIES LABELS "Lab2")

    add_executable(SimpleMACTest ${TESTS_SOURCES_DIR}/SimpleMACTest.cpp)
    target_link_libraries(SimpleMACTest PRIVATE GTest::GTest easylogging)
    add_test(NAME SimpleMACTest COMMAND SimpleMACTest)
    set_tests_properties(SimpleMACTest PROPERTIES LABELS "Lab2")


    execute_process(
        COMMAND bash -c "dd if=/dev/urandom of=${LAB1_TESTS_DATA_DIR}/1MB.bin bs=1M count=1"
    )
    execute_process(
        COMMAND bash -c "dd if=/dev/urandom of=${LAB1_TESTS_DATA_DIR}/100MB.bin bs=1M count=100"
    )
    execute_process(
        COMMAND bash -c "dd if=/dev/urandom of=${LAB1_TESTS_DATA_DIR}/1000MB.bin bs=1M count=1000"
    )
    execute_process(
        COMMAND bash -c "dd if=/dev/urandom of=${LAB1_TESTS_DATA_DIR}/1MBlocks.bin bs=16000000 count=1"
    )
    
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)

        add_library(OpenSSLKuznechikOMAC OBJECT ${SOURCES_DIR}/OpenSSLKuznechikOMAC.cpp)

        add_executable(NMAC256Test ${TESTS_SOURCES_DIR}/NMAC256Test.cpp)
        target_link_libraries(NMAC256Test PRIVATE Streebog OpenSSL::SSL OpenSSL::Crypto GTest::GTest easylogging)
        add_test(NAME NMAC256Test COMMAND NMAC256Test)
        set_tests_properties(NMAC256Test PROPERTIES LABELS "Lab2")

        add_executable(KDF_R_13235651022Test ${TESTS_SOURCES_DIR}/KDF_R_13235651022Test.cpp)
        target_link_libraries(KDF_R_13235651022Test PRIVATE Streebog Kuznechik OpenSSLKuznechikOMAC OpenSSL::SSL OpenSSL::Crypto GTest::GTest easylogging)
        add_test(NAME KDF_R_13235651022Test COMMAND KDF_R_13235651022Test)
        set_tests_properties(KDF_R_13235651022Test PROPERTIES LABELS "Lab2")

        add_executable(CTR_DRBGTest ${TESTS_SOURCES_DIR}/CTR_DRBGTest.cpp)
        target_link_libraries(CTR_DRBGTest PRIVATE OpenSSL::SSL OpenSSL::Crypto GTest::GTest TBB::tbb easylogging)
        add_test(NAME CTR_DRBGTest COMMAND CTR_DRBGTest)
        set_tests_properties(CTR_DRBGTest PROPERTIES LABELS "Lab3")

        add_executable(CTRTest ${TESTS_SOURCES_DIR}/CTRTest.cpp)
        target_link_libraries(CTRTest PRIVATE Kuznechik GTest::GTest TBB::tbb easylogging)
        add_test(NAME CTRTest COMMAND CTRTest)
        set_tests_properties(CTRTest PROPERTIES LABELS "Lab4")

        add_executable(CRISPMessageTest ${TESTS_SOURCES_DIR}/CRISPMessageTest.cpp)
        target_link_libraries(CRISPMessageTest PRIVATE CRISPMessage GTest::GTest)
        add_test(NAME CRISPMessageTest COMMAND CRISPMessageTest)
        set_tests_properties(CRISPMessageTest PROPERTIES LABELS "Lab4")

        find_package(benchmark REQUIRED)

        add_executable(Lab1Test ${TESTS_SOURCES_DIR}/Lab1Test.cpp)
        target_link_libraries(Lab1Test PRIVATE OpenSSL::SSL OpenSSL::Crypto Utils Kuznechik OpenSSLKuznechikOMAC benchmark::benchmark easylogging)

        add_executable(Lab2Test ${TESTS_SOURCES_DIR}/Lab2Test.cpp)
        target_link_libraries(Lab2Test PRIVATE OpenSSL::SSL OpenSSL::Crypto Streebog Kuznechik OpenSSLKuznechikOMAC benchmark::benchmark easylogging)

        add_executable(Lab3Test ${TESTS_SOURCES_DIR}/Lab3Test.cpp)
        target_link_libraries(Lab3Test PRIVATE Kuznechik benchmark::benchmark TBB::tbb easylogging)

    endif()

endif()