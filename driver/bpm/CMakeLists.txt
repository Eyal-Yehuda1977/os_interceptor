cmake_minimum_required(VERSION 3.5)
project(bpm C)

# Add cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake-modules")

# Set C++ flags.
#set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")

#
# Add directories and output
#

include_directories(.)

include_directories(..)

set(SOURCE_FILES
        macros.h
        utils.c
        bpm.h
        bpm.c
        hardening_policy.h
        hardening_policy.c algorithm.h algorithm.c unicode.h)

add_library(bpm ${SOURCE_FILES})
#set_source_files_properties(bpm.c PROPERTIES LANGUAGE CXX )
#set_source_files_properties(hardening_policy.c PROPERTIES LANGUAGE CXX )
#set_target_properties(bpm PROPERTIES LINKER_LANGUAGE CXX)
