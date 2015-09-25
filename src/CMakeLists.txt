INCLUDE(CheckIncludeFiles)
INCLUDE(CheckTypeSize)
CHECK_INCLUDE_FILES(error.h HAVE_ERROR_H)
CHECK_INCLUDE_FILES(err.h HAVE_ERR_H)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

CHECK_TYPE_SIZE(uint8_t UINT8_T)
CHECK_TYPE_SIZE(uint32_t UINT32_T)
CHECK_TYPE_SIZE(uint64_t UINT64_T)
CHECK_TYPE_SIZE(size_t SIZE_T)
CHECK_TYPE_SIZE(ssize_t SSIZE_T)

if(NOT HAVE_UINT8_T)
    unset(HAVE_UINT8_T)
    message(FATAL_ERROR "uint8_t is not found")
endif()

if(NOT HAVE_UINT32_T)
    unset(HAVE_UINT32_T)
    message(FATAL_ERROR "uint32_t is not found")
endif()

if(NOT HAVE_UINT64_T)
    unset(HAVE_UINT64_T)
    message(FATAL_ERROR "uint64_t is not found")
endif()

if(NOT HAVE_SIZE_T)
    unset(HAVE_SIZE_T)
    message(FATAL_ERROR "size_t is not found")
endif()

if(NOT HAVE_SSIZE_T)
    unset(HAVE_SSIZE_T)
    message(FATAL_ERROR "ssize_t is not found")
endif()

set(src_lib
    algo/anubis.c
    algo/cast6.c
    algo/rc6.c
    algo/ripemd.c
    algo/twofish.c
    algo/serpent.c
    algo/sha1.c
    algo/sha2.c
    algo/sha3.c
    algo/threefish_1024.c
    algo/camellia.c
    algo/rijndael.c
    algo/tiger.c
    algo/whirlpool.c
    algo/blowfish.c
    algo/seed.c
    kdf/kdf2.c
    mode/ecb.c
    mode/cbc.c
    mode/hmac.c
    mode/ofb.c
    mode/ctr.c
    mode/cfb.c
    mode/cbc-mac.c
    mode/cmac.c
    xform/cipher.c
    xform/digest.c
    xform/mac.c
    akmos.c
    cipher.c
    digest.c
    mac.c)

set(src_amd64
    algo/amd64/threefish_256.s
    algo/amd64/threefish_512.s
    amd64/pxor.s)

set(src_orig
    algo/threefish_256.c
    algo/threefish_512.c
    pxor.c)

set(src_cli
    cli/main.c
    cli/cipher.c
    cli/digest.c
    cli/secur.c
    cli/mac.c)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
    set(AMD64 TRUE)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "amd64")
    set(AMD64 TRUE)
else()
    set(AMD64 FALSE)
endif()

if(AKMOS_ENABLE_ASM AND AMD64)
    enable_language(ASM-ATT)
    if(CMAKE_ASM-ATT_COMPILER_WORKS)
        list(SORT src_amd64)
        add_library(akmos_obj_asm OBJECT ${src_amd64})
    endif()
else()
    set(src_lib ${src_lib} ${src_orig})
endif()

list(SORT src_lib)
list(SORT src_cli)

add_library(akmos_obj OBJECT ${src_lib})

add_definitions(-D_BSD_SOURCE -D_POSIX_C_SOURCE=199309L -D_XOPEN_SOURCE=500)
add_definitions(-DAKMOS_BUFSZ=8192)
set(CFLAGS "-fPIC -DPIC -ansi -Wall -Werror -Wmissing-prototypes")
separate_arguments(CFLAGS UNIX_COMMAND ${CFLAGS})
target_compile_options(akmos_obj PRIVATE ${CFLAGS})

if(TARGET akmos_obj_asm)
    add_library(akmos_shared SHARED $<TARGET_OBJECTS:akmos_obj> $<TARGET_OBJECTS:akmos_obj_asm>)
    add_library(akmos_static STATIC $<TARGET_OBJECTS:akmos_obj> $<TARGET_OBJECTS:akmos_obj_asm>)
else()
    add_library(akmos_shared SHARED $<TARGET_OBJECTS:akmos_obj>)
    add_library(akmos_static STATIC $<TARGET_OBJECTS:akmos_obj>)
endif()

set_target_properties(akmos_shared PROPERTIES VERSION 0.3 SOVERSION 0 OUTPUT_NAME akmos)
set_target_properties(akmos_static PROPERTIES OUTPUT_NAME akmos)

add_executable(akmos ${src_cli})
target_link_libraries(akmos akmos_shared)

set(BINDIR bin)

install(TARGETS akmos_shared akmos_static akmos
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(FILES akmos.h
        DESTINATION include)
