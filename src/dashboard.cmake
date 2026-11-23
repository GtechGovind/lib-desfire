include("${PROJECT_SOURCE_DIR}/cmake/dashboard_dependencies.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/frontend.cmake")

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_LIST_DIR}/dashboard/commands.json")
file(READ "${CMAKE_CURRENT_LIST_DIR}/dashboard/commands.json" DESFIRE_COMMAND_CATALOG)
string(FIND "${DESFIRE_COMMAND_CATALOG}" ")desfire_catalog\"" desfire_catalog_delimiter)
if(NOT desfire_catalog_delimiter EQUAL -1)
  message(FATAL_ERROR "The command catalog contains the reserved resource delimiter.")
endif()
configure_file("${PROJECT_SOURCE_DIR}/cmake/dashboard_resources.hpp.in"
  "${PROJECT_BINARY_DIR}/generated/dashboard_resources.hpp" @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/cmake/dashboard_resources.cpp.in"
  "${PROJECT_BINARY_DIR}/generated/dashboard_resources.cpp" @ONLY)

set(desfire_dashboard_sources
  dashboard/main.cpp
  application/command_arguments.cpp
  application/command_support.cpp
  application/command_session.cpp
  application/native_commands.cpp
  application/iso_commands.cpp
  application/command_service.cpp
  http/server.cpp
  http/request_guard.cpp
  http/static_assets.cpp
  transport/apdu_codec.cpp
  transport/deadline_exchange.cpp
  transport/pcsc_reader.cpp
)
list(TRANSFORM desfire_dashboard_sources PREPEND "${CMAKE_CURRENT_LIST_DIR}/")
add_executable(desfire_dashboard
  "${PROJECT_BINARY_DIR}/generated/dashboard_resources.cpp"
  ${desfire_dashboard_sources})
add_dependencies(desfire_dashboard desfire_frontend)
target_compile_features(desfire_dashboard PRIVATE cxx_std_17)
target_include_directories(desfire_dashboard PRIVATE "${PROJECT_BINARY_DIR}/generated")
target_include_directories(desfire_dashboard SYSTEM PRIVATE
  "$<TARGET_PROPERTY:httplib::httplib,INTERFACE_INCLUDE_DIRECTORIES>"
  "$<TARGET_PROPERTY:nlohmann_json::nlohmann_json,INTERFACE_INCLUDE_DIRECTORIES>")
target_compile_definitions(desfire_dashboard PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX
  _WIN32_WINNT=0x0A00 WINVER=0x0A00
  DESFIRE_APP_VERSION="${PROJECT_VERSION}")
target_link_libraries(desfire_dashboard PRIVATE
  lib_desfire::core nlohmann_json::nlohmann_json httplib::httplib
  OpenSSL::Crypto Threads::Threads winscard shell32)
if(MSVC)
  target_compile_options(desfire_dashboard PRIVATE /W4 /permissive-)
else()
  target_compile_options(desfire_dashboard PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
endif()

# Run for every application build so changed web assets are staged even when
# no native source requires relinking. It also supports multi-config generators.
add_custom_target(desfire_dashboard_assets ALL
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
    "${desfire_frontend_dir}/dist" "$<TARGET_FILE_DIR:desfire_dashboard>/web"
  DEPENDS desfire_dashboard desfire_frontend
  COMMENT "Staging dashboard web assets"
  VERBATIM)
add_custom_command(TARGET desfire_dashboard POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_directory
    "${desfire_frontend_dir}/dist" "$<TARGET_FILE_DIR:desfire_dashboard>/web"
  VERBATIM)

if(OPENSSL_ROOT_DIR AND WIN32)
  file(GLOB desfire_crypto_runtime "${OPENSSL_ROOT_DIR}/bin/libcrypto*.dll")
  foreach(runtime IN LISTS desfire_crypto_runtime)
    add_custom_command(TARGET desfire_dashboard POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${runtime}"
        "$<TARGET_FILE_DIR:desfire_dashboard>" VERBATIM)
    install(FILES "${runtime}" DESTINATION "${CMAKE_INSTALL_BINDIR}")
  endforeach()
  if(EXISTS "${OPENSSL_ROOT_DIR}/lib/ossl-modules")
    add_custom_command(TARGET desfire_dashboard POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy_directory "${OPENSSL_ROOT_DIR}/lib/ossl-modules"
        "$<TARGET_FILE_DIR:desfire_dashboard>/ossl-modules" VERBATIM)
    install(DIRECTORY "${OPENSSL_ROOT_DIR}/lib/ossl-modules/"
      DESTINATION "${CMAKE_INSTALL_BINDIR}/ossl-modules")
  endif()
endif()
if(MINGW)
  get_filename_component(desfire_compiler_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
  foreach(runtime libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll)
    if(EXISTS "${desfire_compiler_bin}/${runtime}")
      add_custom_command(TARGET desfire_dashboard POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${desfire_compiler_bin}/${runtime}"
          "$<TARGET_FILE_DIR:desfire_dashboard>" VERBATIM)
      install(FILES "${desfire_compiler_bin}/${runtime}"
        DESTINATION "${CMAKE_INSTALL_BINDIR}")
    endif()
  endforeach()
endif()

install(TARGETS desfire_dashboard RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY "${desfire_frontend_dir}/dist/"
  DESTINATION "${CMAKE_INSTALL_BINDIR}/web")
include("${PROJECT_SOURCE_DIR}/cmake/dependency_notices.cmake")
