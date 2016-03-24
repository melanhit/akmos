set(src
    main.c
    path.c
    rand.c
    mode_ecb.c
    digest.c)

set(src_enc
    enc.c)

set(vector
    ecb-anubis-128.bin
    ecb-anubis-192.bin
    ecb-anubis-256.bin
    ecb-anubis-320.bin
    ecb-blowfish-64.bin
    ecb-blowfish-96.bin
    ecb-blowfish-128.bin
    ecb-blowfish-160.bin
    ecb-blowfish-192.bin
    ecb-blowfish-224.bin
    ecb-blowfish-256.bin
    ecb-blowfish-288.bin
    ecb-blowfish-320.bin
    ecb-blowfish-352.bin
    ecb-blowfish-384.bin
    ecb-blowfish-416.bin
    ecb-blowfish-448.bin
    ecb-camellia-128.bin
    ecb-camellia-192.bin
    ecb-camellia-256.bin
    ecb-cast6-128.bin
    ecb-cast6-192.bin
    ecb-cast6-256.bin
    ecb-rc6-128.bin
    ecb-rc6-192.bin
    ecb-rc6-256.bin
    ecb-rijndael-128.bin
    ecb-rijndael-192.bin
    ecb-rijndael-256.bin
    ecb-seed-128.bin
    ecb-serpent-128.bin
    ecb-serpent-192.bin
    ecb-serpent-256.bin
    ecb-threefish-256-256.bin
    ecb-threefish-512-512.bin
    ecb-threefish-1024-1024.bin
    ecb-twofish-128.bin
    ecb-twofish-192.bin
    ecb-twofish-256.bin
    digest-ripemd-160.bin
    digest-ripemd-256.bin
    digest-ripemd-320.bin    
    digest-sha1.bin
    digest-sha2-224.bin
    digest-sha2-256.bin
    digest-sha2-384.bin
    digest-sha2-512.bin
    digest-sha3-224.bin
    digest-sha3-256.bin
    digest-sha3-384.bin
    digest-sha3-512.bin
    digest-tiger.bin
    digest-whirlpool.bin)

list(SORT src)

add_definitions(-D_BSD_SOURCE -D_POSIX_C_SOURCE=199309L -D_XOPEN_SOURCE=500)
add_definitions(-DAKMOS_BUFSZ=8192)

set(CFLAGS "-fPIC -DPIC -ansi -Wall -Werror -Wextra -Wmissing-prototypes -Wconversion")
separate_arguments(CFLAGS UNIX_COMMAND ${CFLAGS})
target_compile_options(akmos_obj PRIVATE ${CFLAGS})

add_executable(akmos_test ${src})
target_link_libraries(akmos_test akmos_shared)

add_custom_target(akmos_test_copy)
foreach(item ${vector})
    add_custom_command(TARGET akmos_test_copy POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/test/vector/${item} ${PROJECT_BINARY_DIR}/test)
endforeach()
add_dependencies(akmos_test akmos_test_copy)
