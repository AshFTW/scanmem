cmake_minimum_required(VERSION 3.9 FATAL_ERROR)
project("scanmem & GameConqueror")
include(CheckIncludeFiles)
include(CheckCSourceRuns)

add_definitions(-D_POSIX_C_SOURCE=199309L -D_GNU_SOURCE)  # AC_USE_SYSTEM_EXTENSIONS

CHECK_INCLUDE_FILES(
        "readline/history.h"
        HAVE_LIBREADLINE)

add_definitions(-DPACKAGE_VERSION="0.17~dev")
add_definitions(-DPACKAGE_BUGREPORT="https://github.com/scanmem/scanmem")
add_definitions(-D__USE_GNU)
add_definitions(-D_GNU_SOURCE)
add_definitions(-DGETTEXT_PACKAGE=GameConqueror)

if(NOT EXISTS "/proc/self/maps")
    message(FATAL_ERROR "This system does not seem to have /proc/pid/maps files.")
endif()

if(EXISTS "/proc/self/mem")
    add_definitions(-DHAVE_PROCMEM=1)
else()
    message(STATUS "This system does not seem to have /proc/pid/mem files.")
    message(STATUS "Falling back to ptrace() only support.")
    add_definitions(-DHAVE_PROCMEM=0)
endif()


# ┌──────────────────────────────────────────────────────────────────┐
# │  Build executable                                                │
# └──────────────────────────────────────────────────────────────────┘
add_subdirectory(libscanmem)
add_subdirectory(test)
#add_subdirectory(gui)
#AM_PATH_PYTHON([2.7])
#AC_CONFIG_FILES([
#        gui/Makefile
#        gui/icons/Makefile
#        gui/consts.py
#        gui/gameconqueror
#        gui/org.freedesktop.gameconqueror.policy.in
#        ])
