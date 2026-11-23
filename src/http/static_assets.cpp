#include "static_assets.hpp"
#include "request_guard.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#endif

namespace desfire_console {
  namespace {
    constexpr std::uintmax_t maximum_asset_size = 8 * 1024 * 1024;
    constexpr std::uintmax_t maximum_asset_total = 32 * 1024 * 1024;
    constexpr std::size_t maximum_asset_count = 128;

    void require_plain_path(
      const std::filesystem::path &path,
      bool directory
    ) {
      std::error_code error;
      const auto status = std::filesystem::symlink_status(path, error);
      if (
        error || std::filesystem::is_symlink(status) ||
        (directory ? !std::filesystem::is_directory(status)
                   : !std::filesystem::is_regular_file(status))
      ) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
#ifdef _WIN32
      const auto attributes = GetFileAttributesW(path.c_str());
      if (
        attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      ) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
#endif
    }

    std::string asset_type(std::string_view name) {
      const auto dot = name.find('.');
      if (dot == std::string_view::npos || dot == 0 || name.size() > 160) {
        return {};
      }
      for (const char character : name.substr(0, dot)) {
        if (!((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') || character == '_' || character == '-')) {
          return {};
        }
      }
      const auto extension = name.substr(dot + 1);
      constexpr std::array<std::pair<std::string_view, std::string_view>, 10> types{
        {{"js", "text/javascript; charset=utf-8"},
         {"css", "text/css; charset=utf-8"},
         {"svg", "image/svg+xml"},
         {"png", "image/png"},
         {"jpg", "image/jpeg"},
         {"jpeg", "image/jpeg"},
         {"webp", "image/webp"},
         {"ico", "image/x-icon"},
         {"woff2", "font/woff2"},
         {"woff", "font/woff"}}
      };
      for (const auto &type : types) {
        if (extension == type.first) {
          return std::string(type.second);
        }
      }
      return {};
    }

    std::string read_asset(
      const std::filesystem::path &path,
      std::uintmax_t &total
    ) {
      require_plain_path(path, false);
#ifdef _WIN32
      struct close_handle {
        void operator()(void *handle) const noexcept { CloseHandle(handle); }
      };

      const auto raw = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
      );
      if (raw == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
      const std::unique_ptr<void, close_handle> file(raw);
      BY_HANDLE_FILE_INFORMATION information{};
      LARGE_INTEGER file_size{};
      if (
        !GetFileInformationByHandle(file.get(), &information) ||
        (information.dwFileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
        GetFileType(file.get()) != FILE_TYPE_DISK || !GetFileSizeEx(file.get(), &file_size) ||
        file_size.QuadPart < 0
      ) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
      // Recheck the opened object itself; following a replaced parent junction
      // between path inspection and open must never expose an outside file.
      const auto required = GetFinalPathNameByHandleW(file.get(), nullptr, 0, FILE_NAME_NORMALIZED);
      if (required == 0 || required > 32768) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
      std::wstring opened_path(static_cast<std::size_t>(required), L'\0');
      const auto written =
        GetFinalPathNameByHandleW(file.get(), opened_path.data(), required, FILE_NAME_NORMALIZED);
      if (written == 0 || written >= required) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
      opened_path.resize(written);
      const auto native_path = path.native();
      const auto expected_path = native_path.compare(0, 4, L"\\\\?\\") == 0 ? native_path
                                 : native_path.compare(0, 2, L"\\\\") == 0
                                   ? L"\\\\?\\UNC\\" + native_path.substr(2)
                                   : L"\\\\?\\" + native_path;
      if (
        CompareStringOrdinal(opened_path.c_str(), -1, expected_path.c_str(), -1, TRUE) != CSTR_EQUAL
      ) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
      const auto size = static_cast<std::uintmax_t>(file_size.QuadPart);
      if (size > maximum_asset_size || size > maximum_asset_total - total) {
        throw std::runtime_error("Dashboard asset size limit exceeded.");
      }
      std::string body(static_cast<std::size_t>(size), '\0');
      DWORD read = 0;
      if (
        !ReadFile(file.get(), body.data(), static_cast<DWORD>(body.size()), &read, nullptr) ||
        read != body.size()
      ) {
        throw std::runtime_error("Dashboard assets changed while loading.");
      }
#else
      std::error_code error;
      const auto size = std::filesystem::file_size(path, error);
      if (error || size > maximum_asset_size || size > maximum_asset_total - total) {
        throw std::runtime_error("Dashboard asset size limit exceeded.");
      }
      std::ifstream input(path, std::ios::binary);
      if (!input) {
        throw std::runtime_error("Dashboard assets are unavailable.");
      }
      std::string body(static_cast<std::size_t>(size), '\0');
      input.read(body.data(), static_cast<std::streamsize>(body.size()));
      if (!input || input.peek() != std::char_traits<char>::eof()) {
        throw std::runtime_error("Dashboard assets changed while loading.");
      }
#endif
      total += size;
      return body;
    }
  }

  static_assets::static_assets(const std::filesystem::path &directory) {
    const auto root = std::filesystem::absolute(directory).lexically_normal();
    // Check ancestors too: Windows junctions are reparse points, rather than
    // symlinks as reported by every filesystem implementation.
    auto ancestor = root;
    while (!ancestor.empty()) {
      require_plain_path(ancestor, true);
      const auto parent = ancestor.parent_path();
      if (parent == ancestor) {
        break;
      }
      ancestor = parent;
    }
    std::uintmax_t total = 0;
    routes_.emplace(
      "/index.html", asset{read_asset(root / "index.html", total), "text/html; charset=utf-8"}
    );
    const auto asset_directory = root / "assets";
    require_plain_path(asset_directory, true);
    for (const auto &entry : std::filesystem::directory_iterator(asset_directory)) {
      const auto filename = entry.path().filename().string();
      auto content_type = asset_type(filename);
      if (content_type.empty()) {
        continue;
      }
      if (routes_.size() >= maximum_asset_count + 1) {
        throw std::runtime_error("Dashboard asset count limit exceeded.");
      }
      routes_.emplace(
        "/assets/" + filename, asset{read_asset(entry.path(), total), std::move(content_type)}
      );
    }
  }

  bool static_assets::serve(
    const std::string &route,
    httplib::Response &response
  ) const {
    const auto found = routes_.find(route == "/" ? "/index.html" : route);
    if (found == routes_.end()) {
      return false;
    }
    response.status = 200;
    response.set_content(found->second.body, found->second.content_type);
    security_headers(response);
    return true;
  }
}
