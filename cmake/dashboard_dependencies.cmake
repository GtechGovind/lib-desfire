include(FetchContent)

# Dashboard dependencies never enter the core library's public interface.
find_package(nlohmann_json 3.12 CONFIG QUIET)
if(NOT TARGET nlohmann_json::nlohmann_json)
  set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
  set(JSON_Install OFF CACHE BOOL "" FORCE)
  set(JSON_SystemInclude ON CACHE BOOL "" FORCE)
  FetchContent_Declare(nlohmann_json
    URL https://github.com/nlohmann/json/archive/refs/tags/v3.12.0.tar.gz
    URL_HASH SHA256=4B92EB0C06D10683F7447CE9406CB97CD4B453BE18D7279320F7B2F025C10187
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  FetchContent_MakeAvailable(nlohmann_json)
endif()

find_package(httplib 0.67 CONFIG QUIET)
if(NOT TARGET httplib::httplib)
  # Loopback HTTP needs neither TLS nor compression. Header-only mode avoids
  # cpp-httplib's optional source-generation runtime dependency.
  set(HTTPLIB_COMPILE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_TEST OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_NON_BLOCKING_GETADDRINFO OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(httplib
    URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.67.0.tar.gz
    URL_HASH SHA256=BE711DDAF7A3655D8F23AA5655709250B24D247AEDD4B2629989D18B6164E5BE
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  FetchContent_MakeAvailable(httplib)
endif()
