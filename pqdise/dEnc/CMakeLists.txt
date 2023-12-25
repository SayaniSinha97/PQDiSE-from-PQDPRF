

file(GLOB_RECURSE SRCS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
 

add_library(dEnc ${SRCS})
find_package(OpenMP)
if(OpenMP_CXX_FOUND)
    target_link_libraries(dEnc PUBLIC OpenMP::OpenMP_CXX)
endif()
target_link_libraries(dEnc PUBLIC oc::cryptoTools)
target_include_directories(dEnc PUBLIC "${CMAKE_CURRENT_LIST_DIR}/..")

