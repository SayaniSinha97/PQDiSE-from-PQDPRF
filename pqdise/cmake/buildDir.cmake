
if(MSVC)
    set(DISE_CONFIG "x64-${CMAKE_BUILD_TYPE}")
elseif(APPLE)
    set(DISE_CONFIG "osx")
else()
    set(DISE_CONFIG "linux")
endif()


if(NOT DISE_BUILD_DIR)
    set(DISE_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/${DISE_CONFIG}")
else()
    if(NOT DEFINED LIBOTE_BUILD_DIR)
        message(STATUS "DISE_BUILD_DIR preset to ${DISE_BUILD_DIR}")
    endif()
endif()

if(NOT EXISTS "${DISE_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the dise build directory. Looked at DISE_BUILD_DIR: ${DISE_BUILD_DIR}")
endif()