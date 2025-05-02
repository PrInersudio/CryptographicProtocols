cmake_minimum_required(VERSION 3.15...4.0)
project(CryptographicProtocols LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CONFIGURATION_TYPES "Debug;Release;UnitTests;DynamicTests" CACHE STRING "" FORCE)
message(STATUS "Сборка в режиме ${CMAKE_BUILD_TYPE}")

# Отмечаем местонахождение исходных файлов.
set(SOURCES_DIR ${CMAKE_SOURCE_DIR}/Sources)
set(TESTS_SOURCES_DIR ${CMAKE_SOURCE_DIR}/TestsSources)
set(LAB1_TESTS_DATA_DIR ${CMAKE_SOURCE_DIR}/Lab1TestsData)
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
add_compile_options(-O3 -static)
add_compile_options(
    $<$<OR:$<CONFIG:Debug>,$<CONFIG:UnitTests>>:-DUNIT_TESTS>
    $<$<CONFIG:Debug>:-fsanitize=address>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:DynamicTests>:-g>
)


if (CMAKE_BUILD_TYPE STREQUAL "DynamicTests")
    add_executable(SecureBufferDynamicTest ${TESTS_SOURCES_DIR}/SecureBufferDynamicTest.cpp)
    return()
endif()

# Сборка модулей.
add_library(Kuznechik OBJECT ${SOURCES_DIR}/Kuznechik.cpp)
add_library(Lab1Utils OBJECT ${SOURCES_DIR}/Lab1Utils.cpp)

# Сборка программ.
add_executable(lab1 ${SOURCES_DIR}/Lab1Main.cpp)
target_link_libraries(lab1 PRIVATE Kuznechik Lab1Utils)

# Сборка тестов.
if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "UnitTests")

    find_package(GTest REQUIRED)
    enable_testing()
    
    add_executable(SecureBufferTest ${TESTS_SOURCES_DIR}/SecureBufferTest.cpp)
    target_link_libraries(SecureBufferTest PRIVATE GTest::GTest)
    add_test(NAME SecureBufferTest COMMAND SecureBufferTest)
    
    add_executable(KuznechikTest ${TESTS_SOURCES_DIR}/KuznechikTest.cpp)
    target_link_libraries(KuznechikTest PRIVATE Kuznechik GTest::GTest)
    add_test(NAME KuznechikTest COMMAND KuznechikTest)

    add_executable(OMACTest ${TESTS_SOURCES_DIR}/OMACTest.cpp)
    target_link_libraries(OMACTest PRIVATE Kuznechik GTest::GTest)
    add_test(NAME OMACTest COMMAND OMACTest)

    add_executable(Lab1UtilsTest ${TESTS_SOURCES_DIR}/Lab1UtilsTest.cpp)
    target_link_libraries(Lab1UtilsTest PRIVATE Lab1Utils Kuznechik GTest::GTest)
    add_test(NAME Lab1UtilsTest COMMAND Lab1UtilsTest)

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
    
    add_executable(Lab1Test ${TESTS_SOURCES_DIR}/Lab1Test.cpp)
    target_link_libraries(Lab1Test PRIVATE Lab1Utils Kuznechik GTest::GTest)

    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        add_executable(Lab1OpensslTest ${TESTS_SOURCES_DIR}/Lab1OpensslTest.cpp)
        target_link_libraries(Lab1OpensslTest PRIVATE OpenSSL::SSL OpenSSL::Crypto  Lab1Utils Kuznechik GTest::GTest)
    endif()

endif()