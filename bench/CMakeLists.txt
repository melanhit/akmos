include(${PROJECT_SOURCE_DIR}/cmake/CheckHeader.txt)
include(${PROJECT_SOURCE_DIR}/cmake/Flags.txt)

find_package(Threads)

set(src
    main.c
    cipher.c
    digest.c)

list(SORT src)

include_directories("${PROJECT_BINARY_DIR}/inc")

set_source_files_properties(${src} PROPERTIES COMPILE_DEFINITIONS "${C_DEFINE}")

add_executable(akmos_bench ${src})
target_compile_options(akmos_bench PUBLIC ${C_FLAGS})
target_link_libraries(akmos_bench akmos_shared ${CMAKE_THREAD_LIBS_INIT})
