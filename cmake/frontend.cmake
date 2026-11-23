find_program(DESFIRE_NPM_EXECUTABLE NAMES npm.cmd npm REQUIRED)
set(desfire_frontend_dir "${PROJECT_SOURCE_DIR}/src/dashboard/frontend")
file(GLOB_RECURSE desfire_frontend_sources CONFIGURE_DEPENDS
  "${desfire_frontend_dir}/src/*.ts"
  "${desfire_frontend_dir}/src/*.tsx"
  "${desfire_frontend_dir}/src/*.css"
)
add_custom_command(
  OUTPUT "${PROJECT_BINARY_DIR}/frontend_dependencies.stamp"
  COMMAND "${DESFIRE_NPM_EXECUTABLE}" ci --no-audit --no-fund
  COMMAND "${CMAKE_COMMAND}" -E touch "${PROJECT_BINARY_DIR}/frontend_dependencies.stamp"
  DEPENDS "${desfire_frontend_dir}/package.json" "${desfire_frontend_dir}/package-lock.json"
  WORKING_DIRECTORY "${desfire_frontend_dir}"
  COMMENT "Installing pinned frontend dependencies"
  VERBATIM
)
add_custom_command(
  OUTPUT "${PROJECT_BINARY_DIR}/frontend_build.stamp"
  COMMAND "${DESFIRE_NPM_EXECUTABLE}" run build
  COMMAND "${CMAKE_COMMAND}" -E touch "${PROJECT_BINARY_DIR}/frontend_build.stamp"
  DEPENDS "${PROJECT_BINARY_DIR}/frontend_dependencies.stamp"
    ${desfire_frontend_sources}
    "${desfire_frontend_dir}/index.html"
    "${desfire_frontend_dir}/tsconfig.json"
  WORKING_DIRECTORY "${desfire_frontend_dir}"
  COMMENT "Building React frontend"
  VERBATIM
)
add_custom_target(desfire_frontend DEPENDS "${PROJECT_BINARY_DIR}/frontend_build.stamp")
