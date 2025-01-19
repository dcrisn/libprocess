cmake_minimum_required(VERSION 3.25)

project( libprocess
    LANGUAGES CXX
    VERSION 0.0.1
    DESCRIPTION "utilities for simplifying working with Linux processes"
)

set( CMAKE_CXX_STANDARD 20 )
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# make Makefiles spit out verbose output by default
set(CMAKE_VERBOSE_MAKEFILE ON)

# Generate compile-commands.json required for clangd language server.
SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(
    -Wall
    -Wextra
    -Wuninitialized
    -Wshadow
    -Wpedantic
    -Wnull-dereference
    -fwrapv
    -fstack-protector-all
    -fstrict-aliasing
    -Wstrict-aliasing
    -fdiagnostics-color=always
    -Wno-format-truncation
    -Wold-style-cast
)

add_definitions(
    -D_POSIX_C_SOURCE=200809L
)

option(BUILD_TESTS "Build tests" OFF)

include(cmake/dependencies.cmake)

add_subdirectory(src)

if (BUILD_TESTS)
    message("Build will include tests")
    add_subdirectory(tests)
endif()


