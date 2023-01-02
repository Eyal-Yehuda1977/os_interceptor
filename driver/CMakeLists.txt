cmake_minimum_required(VERSION 3.5)
project(paranoid_filter C CXX)

execute_process(COMMAND uname -r OUTPUT_VARIABLE TARGET_SYSTEM_NAME OUTPUT_STRIP_TRAILING_WHITESPACE)

#
# Fixups to find the kernel build flags and include paths - mostly for clion project highlight
#
execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check.sh OUTPUT_VARIABLE KERN_DEFS)
execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check.sh -I OUTPUT_VARIABLE KERN_INCS)
string(REGEX REPLACE "\n" ";" KERN_INCS "${KERN_INCS}")
string(REGEX REPLACE "\n" ";" KERN_DEFS "${KERN_DEFS}")
set(KERN_DEFS ${KERN_DEFS} -mcmodel=kernel -fpermissive -fno-builtin -fno-exceptions -fno-rtti -D__UD_STANDALONE__)


#
# Simple wrapper around make
#

# Set this to the location where the driver should be built
set(DRIVER_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/paranoid_filter)

include(AgentVersion)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/driver_version.h.cmake
        ${CMAKE_CURRENT_SOURCE_DIR}/driver_version.h)

# Generate a list of source file.
file(GLOB_RECURSE SRC_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/Makefile
        ${CMAKE_CURRENT_SOURCE_DIR}/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

set ( kofile ${DRIVER_BUILD_DIR}/paranoid_filter.ko )
add_custom_command ( OUTPUT ${DRIVER_BUILD_DIR} ${kofile}
                     COMMAND make -j2 BUILD_DIR=${DRIVER_BUILD_DIR}
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                     DEPENDS ${SRC_FILES}
                     USES_TERMINAL)
add_custom_target ( paranoid_filter ALL DEPENDS ${kofile} SOURCES ${SRC_FILES})

#
# Dummy configuration for clion IDE.
#
add_definitions(${KERN_DEFS})
include_directories(${KERN_INCS})
add_executable(paranoid_filter_dummy EXCLUDE_FROM_ALL ${SRC_FILES} bpm/utils.c)

#
# Install files for packaging.
#
#install(FILES ${kofile} DESTINATION /lib/modules/${TARGET_SYSTEM_NAME}/extra)
install(FILES ${kofile} DESTINATION /usr/bin/)
