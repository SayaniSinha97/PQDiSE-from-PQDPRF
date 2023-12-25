
set(GIT_REPOSITORY      https://github.com/ladnir/cryptoTools.git )
set(GIT_TAG             "84890f04d5a5876daae67b7117f8631db9e26244" )

set(CLONE_DIR "${CMAKE_CURRENT_LIST_DIR}/cryptoTools")
set(BUILD_DIR "${CLONE_DIR}/out/build/${DISE_CONFIG}")
set(CONFIG    --config ${CMAKE_BUILD_TYPE})
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-cryptoTools.txt")

if(MSVC)
    set(MP_ARG "-DMULTI:STRING=OPENMP")
else()
    set(MP_ARG "-DMULTI:STRING=PTHREAD")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")
message("BUILD_DIR: ${BUILD_DIR}")
message("CLONE_DIR: ${CLONE_DIR}")

set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
                       -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
                       -DENABLE_RELIC=ON
                       -DFETCH_RELIC=${FETCH_AUTO}
                       -DFETCH_SPAN_LITE=${FETCH_AUTO}
                       -DFETCH_BOOST=${FETCH_AUTO}
                       ${MP_ARG})
set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} ${CONFIG})
set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} ${CONFIG} --prefix ${DISE_THIRDPARTY_INSTALL_PREFIX})

run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})
message("cryptoTools is fetched.")

install(CODE "
    execute_process(
        COMMAND ${SUDO} \${CMAKE_COMMAND} --install \"${BUILD_DIR}\" ${CONFIG} --prefix \${CMAKE_INSTALL_PREFIX}
        WORKING_DIRECTORY ${CLONE_DIR}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
    )
")