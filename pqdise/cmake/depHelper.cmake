cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)



if(MSVC)
    if(NOT DEFINED CMAKE_BUILD_TYPE)
        set(DISE_BUILD_TYPE "Release")
    elseif(MSVC AND ${CMAKE_BUILD_TYPE} STREQUAL "RelWithDebInfo")
        set(DISE_BUILD_TYPE "Release")
    else()
        set(DISE_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    endif()

    set(DISE_CONFIG "x64-${DISE_BUILD_TYPE}")
elseif(APPLE)
    set(DISE_CONFIG "osx")
else()
    set(DISE_CONFIG "linux")
endif()


if(NOT DEFINED DISE_THIRDPARTY_HINT)

    if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/buildDir.cmake)
        # we currenty are in the cryptoTools source tree, cryptoTools/cmake
        set(DISE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../out/install/${DISE_CONFIG}")
        
        if(NOT DEFINED DISE_THIRDPARTY_INSTALL_PREFIX)
            set(DISE_THIRDPARTY_INSTALL_PREFIX ${DISE_THIRDPARTY_HINT})
        endif()
    else()
        # we currenty are in install tree, <install-prefix>/lib/cmake/cryptoTools
        set(DISE_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()
endif()

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${DISE_THIRDPARTY_HINT};${CMAKE_PREFIX_PATH}")


## cryptoTools
###########################################################################

macro(FIND_CRYPTOTOOLS)
    set(ARGS ${ARGN})
    if(FETCH_CRYPTOTOOLS)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${DISE_THIRDPARTY_HINT})
    endif()
    find_package(cryptoTools ${ARGS})
endmacro()
    
if (FETCH_CRYPTOTOOLS_IMPL)
    FIND_CRYPTOTOOLS(QUIET)
    include("${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getCryptoTools.cmake")
endif()

FIND_CRYPTOTOOLS(REQUIRED)


# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)
