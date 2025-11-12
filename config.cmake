set(PROJECT_NAME "Comp3980Assignment3")
set(PROJECT_VERSION "1.0.0")
set(PROJECT_DESCRIPTION "Comp3980Assignment3")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Common compiler flags
set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        #-D_GNU_SOURCE
        #-D_DARWIN_C_SOURCE
        #-D__BSD_VISIBLE
        -Werror
)

# Define targets
set(EXECUTABLE_TARGETS fsized)
set(LIBRARY_TARGETS "")

set(fsized_SOURCES
        src/fsized.c
)

set(fsized_HEADERS
        include/argumentsd.h
        include/contextd.h
        include/errorsd.h
)

set(fsized_LINK_LIBRARIES
        p101_error
        p101_env
        p101_c
        p101_posix
        p101_unix
        p101_fsm
        p101_convert
        m
)
