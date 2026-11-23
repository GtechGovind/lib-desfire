# Keep upstream notices with redistributed runtime code without copying them
# into the project's authored source tree.
function(desfire_dependency_notice source_file output_name)
  if(EXISTS "${source_file}" OR "${ARGV2}" STREQUAL "GENERATED")
    add_custom_command(TARGET desfire_dashboard POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E make_directory
        "$<TARGET_FILE_DIR:desfire_dashboard>/dependencies"
      COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${source_file}"
        "$<TARGET_FILE_DIR:desfire_dashboard>/dependencies/${output_name}"
      VERBATIM)
    install(FILES "${source_file}" RENAME "${output_name}"
      DESTINATION "${CMAKE_INSTALL_BINDIR}/dependencies")
  endif()
endfunction()

desfire_dependency_notice("${httplib_SOURCE_DIR}/LICENSE" "cpp-httplib.txt")
desfire_dependency_notice("${nlohmann_json_SOURCE_DIR}/LICENSE.MIT" "nlohmann-json.txt")
desfire_dependency_notice("${desfire_frontend_dir}/node_modules/react/LICENSE" "react.txt" GENERATED)
desfire_dependency_notice("${desfire_frontend_dir}/node_modules/react-dom/LICENSE" "react-dom.txt" GENERATED)
desfire_dependency_notice("${desfire_frontend_dir}/node_modules/scheduler/LICENSE" "scheduler.txt" GENERATED)
desfire_dependency_notice("${OPENSSL_ROOT_DIR}/share/licenses/openssl/LICENSE" "openssl.txt")
