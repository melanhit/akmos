cmake_minimum_required(VERSION 3.0)
project(Akmos C ASM)

option(AKMOS_USE_ASM      "Enable assembler optimization" ON)
option(AKMOS_ENABLE_TEST  "Enable test suite" ON)
option(AKMOS_ENABLE_BENCH "Enable benchmark" ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include_directories(src)
add_subdirectory(src)
add_subdirectory(doc/man)

if(AKMOS_ENABLE_TEST)
    add_subdirectory(test)
endif()

if(AKMOS_ENABLE_BENCH)
    add_subdirectory(bench)
endif()
