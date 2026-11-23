cmake_minimum_required(VERSION 3.24)

project(lib_desfire VERSION 0.2.0 LANGUAGES CXX)
include(lib/lib_desfire.cmake)

install(FILES LICENSE
  DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/lib-desfire")

option(lib_desfire_build_dashboard "Build the Windows PC/SC dashboard application" OFF)
if(lib_desfire_build_dashboard)
  if(NOT WIN32)
    message(FATAL_ERROR "The dashboard bridge requires Windows PC/SC.")
  endif()
  include(src/dashboard.cmake)
endif()

include(cmake/source_package.cmake)
