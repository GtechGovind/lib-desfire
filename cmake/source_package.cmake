set(CPACK_PACKAGE_NAME "lib-desfire")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VENDOR "lib-desfire contributors")
set(CPACK_SOURCE_GENERATOR "ZIP")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "lib-desfire-${PROJECT_VERSION}-source")
set(CPACK_SOURCE_IGNORE_FILES
  "/[.]git/" "/[.]idea/" "/[.]vscode/" "/[.]local/" "/[.]private/"
  "/[.]analysis/" "/analysis-work/" "/_site/" "/[.]jekyll-cache/" "/[.]sass-cache/"
  "/build/" "/cmake-build-[^/]+/" "/node_modules/" "/dist/" "/release/" "/install/"
  "/__pycache__/" "/CMakeUserPresets[.]json$"
  "[.](log|pid|pyc|pem|key|pfx|p12)$" "/[.]env([.][^/]*)?$"
)
include(CPack)
