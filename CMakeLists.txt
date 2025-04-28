cmake_minimum_required(VERSION 3.15...4.0)
project(CryptographicProtocols LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
message(STATUS "Сборка в режиме ${CMAKE_BUILD_TYPE}")

# Отмечаем местонахождение исходных файлов.
set(SOURCES_DIR ${CMAKE_SOURCE_DIR}/Sources)
set(TESTS_SOURCES_DIR ${CMAKE_SOURCE_DIR}/TestsSources)
include_directories(${SOURCES_DIR})

if (CMAKE_BUILD_TYPE STREQUAL "DynamicTests")
    set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic -O3 -g")
    add_executable(SecureBufferDynamicTest ${TESTS_SOURCES_DIR}/SecureBufferDynamicTest.cpp)
    return()
endif()

# Флаги
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wpedantic -O3")
if (CMAKE_BUILD_TYPE STREQUAL "UnitTests")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUNIT_TESTS")
endif()
set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_CXX_FLAGS} -fsanitize=address -g -DUNIT_TESTS")

# Сборка модулей.
add_library(GFElement OBJECT ${SOURCES_DIR}/GFElement.cpp)
add_library(Kuznechik OBJECT ${SOURCES_DIR}/Kuznechik.cpp)
add_library(Lab1Utils OBJECT ${SOURCES_DIR}/Lab1Utils.cpp)

# Сборка программ.
add_executable(lab1 ${SOURCES_DIR}/Lab1Main.cpp)
target_link_libraries(lab1 PRIVATE GFElement Kuznechik Lab1Utils)

# Сборка тестов.
if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "UnitTests")

    find_package(GTest REQUIRED)
    enable_testing()
    
    add_executable(SecureBufferTest ${TESTS_SOURCES_DIR}/SecureBufferTest.cpp)
    target_link_libraries(SecureBufferTest PRIVATE GTest::GTest)
    add_test(NAME SecureBufferTest COMMAND SecureBufferTest)
    
    add_executable(GFElementTest ${TESTS_SOURCES_DIR}/GFElementTest.cpp)
    target_link_libraries(GFElementTest PRIVATE GFElement GTest::GTest)
    add_test(NAME GFElementTest COMMAND GFElementTest)

    add_executable(KuznechikTest ${TESTS_SOURCES_DIR}/KuznechikTest.cpp)
    target_link_libraries(KuznechikTest PRIVATE Kuznechik GFElement GTest::GTest)
    add_test(NAME KuznechikTest COMMAND KuznechikTest)

    add_executable(OMACTest ${TESTS_SOURCES_DIR}/OMACTest.cpp)
    target_link_libraries(OMACTest PRIVATE Kuznechik GFElement GTest::GTest)
    add_test(NAME OMACTest COMMAND OMACTest)

    add_executable(Lab1UtilsTest ${TESTS_SOURCES_DIR}/Lab1UtilsTest.cpp)
    target_link_libraries(Lab1UtilsTest PRIVATE Lab1Utils Kuznechik GFElement GTest::GTest)
    add_test(NAME Lab1UtilsTest COMMAND Lab1UtilsTest)

    add_executable(Lab1Test ${TESTS_SOURCES_DIR}/Lab1Test.cpp)
    target_link_libraries(Lab1Test PRIVATE Lab1Utils Kuznechik GFElement GTest::GTest)

    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        add_executable(Lab1OpensslTest ${TESTS_SOURCES_DIR}/Lab1OpensslTest.cpp)
        target_link_libraries(Lab1OpensslTest PRIVATE OpenSSL::SSL OpenSSL::Crypto  Lab1Utils Kuznechik GFElement GTest::GTest)
    endif()

endif()