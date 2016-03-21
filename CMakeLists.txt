cmake_minimum_required(VERSION 2.8)
project(Akmos C)

option(AKMOS_USE_ASM     "Enable assembler optimization" ON)
option(AKMOS_ENABLE_TEST "Enable test suite" ON)

set(CMAKE_C_FLAGS_DEBUG "-O0 -g3")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include_directories(src)
add_subdirectory(src)
add_subdirectory(doc/man)

if(AKMOS_ENABLE_TEST)
    add_subdirectory(test)
endif()
