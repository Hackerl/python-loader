cmake_minimum_required(VERSION 3.17)
project(python_loader)

set(CMAKE_CXX_STANDARD 17)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(MI_BUILD_TESTS OFF CACHE BOOL "disable mimalloc tests")
set(MI_BUILD_SHARED OFF CACHE BOOL "disable mimalloc shared library")
set(MI_BUILD_OBJECT OFF CACHE BOOL "disable mimalloc object library")

if (STATIC_BUILD)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif ()

include(FetchContent)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG c29ab5893259348735eacb8fa6da3415eeaf92ad
)

FetchContent_MakeAvailable(zero)

FetchContent_Declare(
        elf
        GIT_REPOSITORY https://github.com/Hackerl/elf
        GIT_TAG cbf7f5ffb5a3c07f6a8f02d5fc9e425dca572bbc
)

FetchContent_MakeAvailable(elf)

FetchContent_Declare(
        trap
        GIT_REPOSITORY https://github.com/Hackerl/trap
        GIT_TAG 3ae6f308ca092a81fe8b8ecab670a789e76048b8
)

FetchContent_MakeAvailable(trap)

FetchContent_Declare(
        mimalloc
        GIT_REPOSITORY https://github.com/microsoft/mimalloc
        GIT_TAG v2.0.9
)

FetchContent_MakeAvailable(mimalloc)

add_executable(python_loader main.cpp)

target_link_libraries(
        python_loader
        PUBLIC
        zero
        elf_cpp
        trap
        mimalloc-static
        $<$<BOOL:${STATIC_BUILD}>:-static-pie>
)