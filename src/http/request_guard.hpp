#pragma once

#include <cstddef>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

namespace desfire_console {
  inline constexpr std::size_t maximum_request_body = 64 * 1024;

  class request_error final : public std::runtime_error {

  public:

    request_error(
      int status,
      std::string code,
      const char *message
    );
    int status() const noexcept;
    const std::string &code() const noexcept;

  private:

    int status_;
    std::string code_;
  };

  // Applies before any body read or service operation. No proxy headers are trusted.
  class request_guard final {

  public:

    explicit request_guard(unsigned short port);
    void validate_source(const httplib::Request &request) const;
    void authorize(
      const httplib::Request &request,
      bool require_origin
    ) const;
    std::size_t command_body_size(const httplib::Request &request) const;
    const std::string &origin() const noexcept;
    const std::string &token() const noexcept;

  private:

    std::string authority_;
    std::string origin_;
    std::string token_;
  };

  nlohmann::json parse_request_json(std::string_view body);
  void security_headers(httplib::Response &response);
  void json_response(
    httplib::Response &response,
    int status,
    const nlohmann::json &payload
  );
  void error_response(
    httplib::Response &response,
    const request_error &error
  );
  void erase_request_strings(nlohmann::json &value) noexcept;
}
