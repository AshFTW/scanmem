project(libscanmem)

set(CMAKE_C_STANDARD 99)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/)

add_library(libscanmem
        commands.h      commands.c
        common.h        
        endianness.h    
        getline.h       getline.c
        handlers.h      handlers.c
        interrupt.h     interrupt.c
        licence.h       
        list.h          
        maps.h          maps.c
        ptrace.c        
        readline.h      readline.c
        scanmem.h       scanmem.c
        scanroutines.h  scanroutines.c
        sets.h          sets.c
        show_message.h  show_message.c
        targetmem.h
        value.h         value.c
        )

add_executable(scanmem
        main.c
        menu.h          menu.c
        )

target_link_libraries(scanmem
        libscanmem
        readline
        )

target_compile_options(scanmem PRIVATE -Wall)
