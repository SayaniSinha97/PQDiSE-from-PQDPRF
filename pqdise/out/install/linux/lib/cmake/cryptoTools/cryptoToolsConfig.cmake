
####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was Config.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

####################################################################################

include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsTargets.cmake")


set(ENABLE_SPAN_LITE ON)
set(ENABLE_RELIC     ON)
set(ENABLE_SODIUM    OFF)
set(ENABLE_CIRCUITS  OFF)
set(ENABLE_NET_LOG   OFF)
set(ENABLE_WOLFSSL   OFF)
set(ENABLE_SSE       ON)
set(ENABLE_BOOST     ON)

include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsDepHelper.cmake")

