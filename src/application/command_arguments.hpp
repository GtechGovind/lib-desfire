/// @file
/// @brief Catalog schema and bounded, locally validated command arguments.

#ifndef desfire_console_command_arguments_hpp
#define desfire_console_command_arguments_hpp

#include "command_support.hpp"
#include <map>
#include <optional>
#include <vector>

namespace desfire_console::detail {
  using arguments = std::map<std::string, std::string, std::less<>>;

  struct field_spec final {
    std::string name;
    std::string type;
    std::string fallback;
    bool required{false};
    std::optional<std::size_t> width;
    std::int64_t minimum{0};
    std::int64_t maximum{0};
    std::vector<std::string> options;
  };

  struct command_spec final {
    std::string name;
    std::string protocol;
    bool mutating{false};
    std::vector<field_spec> fields;
  };

  /// Request-owned copies are erased even if validation or a handler throws.
  /// The input JSON remains owned by the caller, which must manage its own lifetime.
  struct command_request final {
    const command_spec *spec{nullptr};
    arguments args;
    std::optional<std::string> expected_revision;
    command_request() = default;
    command_request(const command_request &) = delete;
    command_request &operator=(const command_request &) = delete;

    ~command_request() {
      for (auto &entry : args) {
        erase(entry.second);
      }
    }
  };

  struct confirmation_required final : std::exception {
    const char *what() const noexcept override {
      return "Review and confirm this command before sending it";
    }
  };

  struct stale_session final : std::exception {
    const char *what() const noexcept override {
      return "Session changed; refresh its state before sending this command";
    }
  };

  /// Immutable schema compiled from the embedded catalog; never performs I/O.
  class command_catalog final {
    std::map<std::string, command_spec, std::less<>> commands_;

  public:

    explicit command_catalog(const json &catalog);
    void validate(
      const json &input,
      command_request &output
    ) const;
  };

  std::uint32_t number(
    const arguments &args,
    std::string_view name
  );
  std::uint32_t hex_integer(
    const arguments &args,
    std::string_view name
  );
  const std::string &argument(
    const arguments &args,
    std::string_view name
  );
  desfire::communication_mode communication(const arguments &args);
  desfire::access_rights access(const arguments &args);
  std::optional<std::uint16_t> optional_iso_id(const arguments &args);
  std::optional<std::uint8_t> short_id(const arguments &args);
}

#endif
