include(CMake/CheckHeader.txt)
include(CMake/CheckSize.txt)
include(CMake/CheckSymbol.txt)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/inc/config.h)

set(src_lib
    algo/anubis.c
    algo/anubis_sbox.c
    algo/cast6.c
    algo/cast6_sbox.c
    algo/rc6.c
    algo/ripemd.c
    algo/twofish.c
    algo/twofish_sbox.c
    algo/serpent.c
    algo/sha1.c
    algo/sha2.c
    algo/sha3.c
    algo/threefish_1024.c
    algo/camellia.c
    algo/camellia_sbox.c
    algo/rijndael.c
    algo/rijndael_sbox.c
    algo/tiger.c
    algo/tiger_sbox.c
    algo/whirlpool.c
    algo/whirlpool_sbox.c
    algo/blowfish.c
    algo/blowfish_sbox.c
    algo/seed.c
    algo/seed_sbox.c
    algo/chacha.c
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
    algo/amd64/sha3_transform.s
    algo/amd64/salsa_sse2.s
    amd64/pxor.s)

set(src_orig
    algo/threefish_256.c
    algo/threefish_512.c
    algo/sha3_transform.c
    algo/salsa.c
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

if(AKMOS_USE_ASM AND AMD64)
    enable_language(ASM-ATT)
    if(CMAKE_ASM-ATT_COMPILER_WORKS)
        list(SORT src_amd64)
        add_library(akmos_obj_asm OBJECT ${src_amd64})
        add_definitions(-DAKMOS_ASM -DAKMOS_ASM_SSE2)
    endif()
else()
    set(src_lib ${src_lib} ${src_orig})
endif()

list(SORT src_lib)
list(SORT src_cli)

add_library(akmos_obj OBJECT ${src_lib})

add_definitions(-D_BSD_SOURCE -D_POSIX_C_SOURCE=199309L -D_XOPEN_SOURCE=500)
add_definitions(-DAKMOS_BUFSZ=8192)
include_directories("${PROJECT_BINARY_DIR}/inc")
target_compile_options(akmos_obj PUBLIC -fPIC -ansi -Wall -Wextra -Werror -Wmissing-prototypes -Wconversion)

if(TARGET akmos_obj_asm)
    add_library(akmos_shared SHARED $<TARGET_OBJECTS:akmos_obj> $<TARGET_OBJECTS:akmos_obj_asm>)
    add_library(akmos_static STATIC $<TARGET_OBJECTS:akmos_obj> $<TARGET_OBJECTS:akmos_obj_asm>)
else()
    add_library(akmos_shared SHARED $<TARGET_OBJECTS:akmos_obj>)
    add_library(akmos_static STATIC $<TARGET_OBJECTS:akmos_obj>)
endif()

set_target_properties(akmos_shared PROPERTIES VERSION 0.6 SOVERSION 6 OUTPUT_NAME akmos)
set_target_properties(akmos_static PROPERTIES OUTPUT_NAME akmos)

add_executable(akmos ${src_cli})
target_compile_options(akmos PUBLIC -fPIC -ansi -Wall -Wextra -Werror -Wmissing-prototypes -Wconversion)
target_link_libraries(akmos akmos_shared)

set(BINDIR bin)

install(TARGETS akmos_shared akmos_static akmos
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin)
install(FILES akmos.h
        DESTINATION include)
