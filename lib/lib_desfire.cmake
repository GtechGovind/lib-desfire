include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

option(lib_desfire_build_shared "Build a shared core library" OFF)

set(lib_desfire_library_type STATIC)
if(lib_desfire_build_shared)
  set(lib_desfire_library_type SHARED)
endif()

file(GLOB_RECURSE lib_desfire_sources CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_LIST_DIR}/impl/*.cpp"
)
add_library(lib_desfire ${lib_desfire_library_type} ${lib_desfire_sources})
add_library(lib_desfire::core ALIAS lib_desfire)
set_target_properties(lib_desfire PROPERTIES
  EXPORT_NAME core
  OUTPUT_NAME desfire
  POSITION_INDEPENDENT_CODE ON
  WINDOWS_EXPORT_ALL_SYMBOLS ON
)
target_compile_features(lib_desfire PUBLIC cxx_std_17)
target_include_directories(lib_desfire PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(lib_desfire PRIVATE OpenSSL::Crypto Threads::Threads)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(lib_desfire PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
  )
elseif(MSVC)
  target_compile_options(lib_desfire PRIVATE /W4)
endif()

set(lib_desfire_package_directory "${CMAKE_INSTALL_LIBDIR}/cmake/lib_desfire")
install(TARGETS lib_desfire EXPORT lib_desfire_targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/include/"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(EXPORT lib_desfire_targets
  NAMESPACE lib_desfire::
  DESTINATION ${lib_desfire_package_directory}
)

# CMake's package discovery requires Config/ConfigVersion spelling. Keep this
# external naming convention even though project-owned sources use snake_case.
configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/lib_desfire_config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/lib_desfireConfig.cmake"
  INSTALL_DESTINATION ${lib_desfire_package_directory}
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/lib_desfireConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/lib_desfireConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/lib_desfireConfigVersion.cmake"
  DESTINATION ${lib_desfire_package_directory}
)
