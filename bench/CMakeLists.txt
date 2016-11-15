
CHECK_INCLUDE_FILES(time.h HAVE_TIME_H)

if(NOT HAVE_TIME_H)
    unset(HAVE_TIME_H)
    message(FATAL_ERROR "<time.h> is not found")
endif()

find_package(Threads)

set(src
    main.c
    cipher.c
    digest.c)

list(SORT src)

include_directories("${PROJECT_BINARY_DIR}/inc")
add_definitions(-D_BSD_SOURCE -D_POSIX_C_SOURCE=199309L -D_XOPEN_SOURCE=500)
add_definitions(-DAKMOS_BUFSZ=8192)

add_executable(akmos_bench ${src})
target_compile_options(akmos_bench PUBLIC -fPIC -ansi -Wall -Wextra -Werror -Wmissing-prototypes -Wconversion)
target_link_libraries(akmos_bench akmos_shared ${CMAKE_THREAD_LIBS_INIT})
