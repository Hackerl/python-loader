cmake_minimum_required(VERSION 3.21)
project(python_loader)

set(CMAKE_CXX_STANDARD 14)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "disable disassembler tools")
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "disable disassembler examples")

include(FetchContent)

FetchContent_Declare(
        ELFIO
        GIT_REPOSITORY https://github.com/serge1/ELFIO
        GIT_TAG master
)

FetchContent_MakeAvailable(ELFIO)

FetchContent_Declare(
        zydis
        GIT_REPOSITORY https://github.com/zyantific/zydis
        GIT_TAG v3.1.0
)

FetchContent_MakeAvailable(zydis)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG master
)

FetchContent_MakeAvailable(zero)

FetchContent_Declare(
        c-runtime
        GIT_REPOSITORY https://github.com/Hackerl/c-runtime
        GIT_TAG master
)

FetchContent_MakeAvailable(c-runtime)

add_executable(python_loader main.cpp asm/inline_hook.cpp heap/memory.cpp)
target_link_libraries(python_loader zero c_runtime elfio Zydis $<$<BOOL:${STATIC_BUILD}>:-static-pie>)