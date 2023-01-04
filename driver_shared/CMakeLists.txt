cmake_minimum_required(VERSION 3.5)
project(agentDriverShared CXX)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES
        driver_api.h)

# LM: If this library holds more than headers then use "add_library" instead of "add_custom_target"
#add_library(agentDriverShared ${SOURCE_FILES})
add_custom_target(agentDriverShared SOURCES ${SOURCE_FILES})
set_target_properties(agentDriverShared PROPERTIES LINKER_LANGUAGE CXX)
