cmake_minimum_required (VERSION 3.5)

project("dEnc")

#############################################
#            Flag and #defines              #
#############################################
add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")

# Set a default build type for single-configuration
# CMake generators if no build type is set.

set(CMAKE_C_FLAGS "-ffunction-sections -Wall -Wno-strict-aliasing -maes -msse2 -msse4.1 -mpclmul -Wno-sign-compare -Wfatal-errors -pthread")
set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14 -Wno-ignored-attributes")
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE Release)
endif()


if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with -DCMAKE_BUILD_TYPE=Release  instead of ${CMAKE_BUILD_TYPE}")

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
      message(WARNING "Debug build.")
    elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release") 
      message(WARNING "Release build.")
    elseif("${CMAKE_BUILD_TYPE}" STREQUAL  "RELWITHDEBINFO")
      message(WARNING "RELWITHDEBINFO=Release with debug info build.")
    else()
      message(ERROR ": Unknown build type - ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO\n\n" )
    endif()

endif()

message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRELWITHDEBINFO")


include("${CMAKE_CURRENT_LIST_DIR}/cmake/buildOptions.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmake/depHelper.cmake")

#############################################
#               Build libPSI                 #
#############################################
add_subdirectory(dEnc)

#############################################
#           Build libPSI Tests              #
#############################################
add_subdirectory(dEnc_tests)

#############################################
#              Build Frontend               #
#############################################
add_subdirectory(dEncFrontend)


