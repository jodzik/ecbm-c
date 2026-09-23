cmake_minimum_required(VERSION 3.28)

project(ecbm-c C)

set(CMAKE_C_STANDARD 11)
#set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} SRC)

if(DEFINED ENV{ZEPHYR_BASE})
    target_sources(app PRIVATE ${SRC})
    target_include_directories(app PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
else()
    add_library(ecbm-c STATIC)
    target_sources(ecbm-c PRIVATE ${SRC})
    target_link_libraries(ecbm-c safe-c byteorder-c crc-c framer7b-c)
    target_include_directories(ecbm-c PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

    target_compile_options(ecbm-c PRIVATE -Wall -Wextra -Werror -Wno-missing-field-initializers -Wno-unused-value -Wno-unused-function -Wno-missing-braces)

    option(BUILD_TESTS "Build tests" OFF)
    if(BUILD_TESTS)
        add_subdirectory(TEST)
    endif()
endif()
