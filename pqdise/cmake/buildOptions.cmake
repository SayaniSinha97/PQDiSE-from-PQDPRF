



add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")

if(NOT DEFINED DISE_CXX_FLAGS AND NOT MSVC)

	set(DISE_C_FLAGS "-lntl -ffunction-sections -Wall -Wno-strict-aliasing -maes -msse2 -msse4.1 -mpclmul -Wno-sign-compare -Wfatal-errors -pthread")
	set(DISE_CXX_FLAGS  "${DISE_C_FLAGS}  -std=c++14 -Wno-ignored-attributes")

	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -ggdb -rdynamic")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g3 -ggdb -rdynamic")


	set(CMAKE_CXX_FLAGS  "${DISE_CXX_FLAGS}")
	set(CMAKE_C_FLAGS "${DISE_C_FLAGS}")
	message("CMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}")
endif()


macro(EVAL var)
     if(${ARGN})
         set(${var} ON)
     else()
         set(${var} OFF)
     endif()
endmacro()



option(FETCH_AUTO      "automatically download and build dependencies" OFF)

#option(FETCH_SPAN_LITE		"download and build span" OFF))
EVAL(FETCH_CRYPTOTOOLS_IMPL 
	(DEFINED FETCH_CRYPTOTOOLS AND FETCH_CRYPTOTOOLS) OR
	((NOT DEFINED FETCH_CRYPTOTOOLS) AND FETCH_AUTO))

message(STATUS "cryptoTools options\n=======================================================")

message(STATUS "Option: FETCH_AUTO        = ${FETCH_AUTO}")
message(STATUS "Option: VERBOSE_FETCH     = ${VERBOSE_FETCH}\n")

message(STATUS "Option: FETCH_CRYPTOTOOLS = ${FETCH_CRYPTOTOOLS}")