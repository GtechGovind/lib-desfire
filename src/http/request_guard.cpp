#include "request_guard.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace desfire_console {
  namespace {
    std::string random_token() {
      std::array<unsigned char, 32> random{};
      if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        throw std::runtime_error("Session initialization failed.");
      }
      constexpr std::string_view hex = "0123456789abcdef";
      std::string result;
      result.reserve(random.size() * 2);
      for (const auto byte : random) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
      }
      OPENSSL_cleanse(random.data(), random.size());
      return result;
    }

    std::string ascii_lower(std::string value) {
      for (auto &character : value) {
        if (character >= 'A' && character <= 'Z') {
          character = static_cast<char>(character - 'A' + 'a');
        }
      }
      return value;
    }

    std::string_view trim_ascii(std::string_view value) {
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
      }
      while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
      }
      return value;
    }

    bool valid_referer(
      std::string_view referer,
      std::string_view origin
    ) {
      // Exact authority and scheme matching also rejects credentials, alternative IP
      // spellings and authority suffixes. Only an ordinary same-origin URL may follow.
      if (referer.substr(0, origin.size()) != origin) {
        return false;
      }
      const auto suffix = referer.substr(origin.size());
      if (
        !suffix.empty() && suffix.front() != '/' && suffix.front() != '?' && suffix.front() != '#'
      ) {
        return false;
      }
      return std::none_of(referer.begin(), referer.end(), [](unsigned char c) {
        return c < 0x21 || c == 0x7f || c == '\\';
      });
    }
  }

  request_error::request_error(
    int status,
    std::string code,
    const char *message
  )
      : std::runtime_error(message),
        status_(status),
        code_(std::move(code)) {}

  int request_error::status() const noexcept {
    return status_;
  }

  const std::string &request_error::code() const noexcept {
    return code_;
  }

  request_guard::request_guard(unsigned short port)
      : authority_(port == 80 ? "127.0.0.1" : "127.0.0.1:" + std::to_string(port)),
        origin_("http://" + authority_),
        token_(random_token()) {}

  void request_guard::validate_source(const httplib::Request &request) const {
    // Reject every duplicated header, not merely the security-sensitive subset.
    std::unordered_set<std::string> names;
    for (const auto &header : request.headers) {
      if (!names.insert(ascii_lower(header.first)).second) {
        throw request_error(400, "invalid_headers", "Duplicate request header.");
      }
    }
    if (request.remote_addr != "127.0.0.1" || request.get_header_value("Host") != authority_) {
      throw request_error(403, "invalid_host", "Use the console's 127.0.0.1 address.");
    }
    if (request.has_header("Origin") && request.get_header_value("Origin") != origin_) {
      throw request_error(403, "invalid_origin", "Cross-origin requests are not allowed.");
    }
    if (
      request.has_header("Referer") && !valid_referer(request.get_header_value("Referer"), origin_)
    ) {
      throw request_error(403, "invalid_origin", "Cross-origin requests are not allowed.");
    }
    if (request.has_header("Sec-Fetch-Site")) {
      const auto site = request.get_header_value("Sec-Fetch-Site");
      if (site != "none" && site != "same-origin") {
        throw request_error(403, "invalid_origin", "Cross-origin requests are not allowed.");
      }
    }
    if (request.has_header("Transfer-Encoding") || request.has_header("Content-Encoding")) {
      throw request_error(400, "invalid_headers", "Encoded request bodies are not supported.");
    }
    // cpp-httplib decodes req.path. Equality with the original target ensures the
    // route table never accepts encoded paths, queries, fragments or absolute URIs.
    if (
      request.target != request.path || request.path.find_first_of("%?#\\") != std::string::npos
    ) {
      throw request_error(404, "not_found", "Route not found.");
    }
    if (request.method != "GET" && request.method != "POST") {
      throw request_error(405, "method_not_allowed", "This HTTP method is not allowed.");
    }
    if (
      request.method == "GET" && request.has_header("Content-Length") &&
      request.get_header_value("Content-Length") != "0"
    ) {
      throw request_error(400, "invalid_body", "GET requests must not contain a body.");
    }
  }

  void request_guard::authorize(
    const httplib::Request &request,
    bool require_origin
  ) const {
    if (require_origin && request.get_header_value("Origin") != origin_) {
      throw request_error(403, "invalid_origin", "An exact same-origin request is required.");
    }
    const auto supplied = request.get_header_value("X-Session-Token");
    if (
      supplied.size() != token_.size() ||
      CRYPTO_memcmp(supplied.data(), token_.data(), token_.size()) != 0
    ) {
      throw request_error(403, "invalid_token", "A valid console session token is required.");
    }
  }

  std::size_t request_guard::command_body_size(const httplib::Request &request) const {
    const auto content_type = request.get_header_value("Content-Type");
    const auto separator = content_type.find(';');
    if (
      ascii_lower(std::string(trim_ascii(std::string_view(content_type).substr(0, separator)))) !=
      "application/json"
    ) {
      throw request_error(415, "invalid_content_type", "Use application/json.");
    }
    const auto length = request.get_header_value("Content-Length");
    if (
      length.empty() || length.size() > 10 || std::any_of(length.begin(), length.end(), [](char c) {
        return c < '0' || c > '9';
      })
    ) {
      throw request_error(411, "length_required", "A valid Content-Length is required.");
    }
    std::uint64_t size = 0;
    const auto conversion = std::from_chars(length.data(), length.data() + length.size(), size);
    if (conversion.ec != std::errc{} || conversion.ptr != length.data() + length.size()) {
      throw request_error(411, "length_required", "A valid Content-Length is required.");
    }
    if (size > maximum_request_body) {
      throw request_error(413, "body_too_large", "The request body exceeds 64 KiB.");
    }
    return static_cast<std::size_t>(size);
  }

  const std::string &request_guard::origin() const noexcept {
    return origin_;
  }

  const std::string &request_guard::token() const noexcept {
    return token_;
  }

  nlohmann::json parse_request_json(std::string_view body) {
    std::vector<std::unordered_set<std::string>> object_keys;
    const auto callback =
      [&object_keys](int depth, nlohmann::json::parse_event_t event, nlohmann::json &value) {
        if (depth > 64) {
          throw request_error(400, "invalid_json", "The JSON body is too deeply nested.");
        }
        if (event == nlohmann::json::parse_event_t::object_start) {
          object_keys.emplace_back();
        } else if (event == nlohmann::json::parse_event_t::object_end) {
          object_keys.pop_back();
        } else if (
          event == nlohmann::json::parse_event_t::key &&
          !object_keys.back().insert(value.get<std::string>()).second
        ) {
          throw request_error(400, "invalid_json", "Duplicate JSON properties are not allowed.");
        }
        return true;
      };
    try {
      return nlohmann::json::parse(body.begin(), body.end(), callback);
    } catch (const nlohmann::json::exception &) {
      throw request_error(400, "invalid_json", "The request body must be valid UTF-8 JSON.");
    }
  }

  void security_headers(httplib::Response &response) {
    const auto set = [&response](const char *name, const char *value) {
      response.headers.erase(name);
      response.set_header(name, value);
    };
    set("Cache-Control", "no-store, max-age=0");
    set("Pragma", "no-cache");
    set("X-Content-Type-Options", "nosniff");
    set("X-Frame-Options", "DENY");
    set("Referrer-Policy", "no-referrer");
    set("Cross-Origin-Opener-Policy", "same-origin");
    set("Cross-Origin-Resource-Policy", "same-origin");
    set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), serial=()");
    set(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
      "img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; "
      "frame-ancestors 'none'"
    );
    set("Connection", "close");
  }

  void json_response(
    httplib::Response &response,
    int status,
    const nlohmann::json &payload
  ) {
    response.status = status;
    response.headers.erase("Content-Type");
    response.set_content(payload.dump(-1, ' ', true), "application/json; charset=utf-8");
    security_headers(response);
  }

  void error_response(
    httplib::Response &response,
    const request_error &error
  ) {
    json_response(
      response,
      error.status(),
      {{"ok", false}, {"error", {{"code", error.code()}, {"message", error.what()}}}}
    );
  }

  void erase_request_strings(nlohmann::json &value) noexcept {
    if (value.is_string()) {
      auto &text = value.get_ref<std::string &>();
      if (!text.empty()) {
        OPENSSL_cleanse(text.data(), text.size());
      }
    } else if (value.is_structured()) {
      for (auto &child : value) {
        erase_request_strings(child);
      }
    }
  }
}
