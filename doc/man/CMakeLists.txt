set(man1_src
    akmos.1)

list(SORT man1_src)

foreach(man ${man1_src})
    add_custom_command(OUTPUT ${man}
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${man} ${CMAKE_CURRENT_BINARY_DIR}
            COMMAND gzip -f -c ${CMAKE_CURRENT_BINARY_DIR}/${man} > ${CMAKE_CURRENT_BINARY_DIR}/${man}.gz
            MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/${man})
endforeach()

add_custom_target(manpage ALL
        DEPENDS ${man1_src})

foreach(manpage ${man1_src})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${manpage}.gz
            DESTINATION man/man1)
endforeach()
