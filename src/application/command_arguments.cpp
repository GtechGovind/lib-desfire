/// @file
/// @brief Validate all request fields and protocol relationships before dispatch.

#include "command_arguments.hpp"
#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace desfire_console::detail {
  namespace {
    constexpr std::size_t maximum_hex_size = 16384;
    constexpr std::uint64_t maximum_native_range = 0xffffff;
    constexpr std::uint64_t maximum_response_size = desfire::card_options{}.max_response_size;
    constexpr std::array<std::string_view, 58> supported_commands = {
      "list_readers",
      "connect",
      "disconnect",
      "status",
      "credential_list",
      "credential_add",
      "credential_remove",
      "init",
      "get_version",
      "free_memory",
      "get_card_uid",
      "get_application_ids",
      "get_df_names",
      "get_fids",
      "get_iso_fids",
      "get_key_settings",
      "select_application",
      "create_application",
      "delete_application",
      "format_picc",
      "set_configuration",
      "get_key_version",
      "change_key_settings",
      "authenticate",
      "authenticate_iso",
      "authenticate_aes",
      "change_picc_master_key",
      "change_app_key",
      "get_file_settings",
      "change_file_settings",
      "create_std_data_file",
      "create_backup_data_file",
      "create_value_file",
      "create_linear_record_file",
      "create_cyclic_record_file",
      "delete_file",
      "read_data",
      "write_data",
      "get_value",
      "credit",
      "debit",
      "limited_credit",
      "read_records",
      "write_record",
      "clear_record_file",
      "commit_transaction",
      "abort_transaction",
      "iso7816_select_master_file",
      "iso7816_select_file",
      "iso7816_select_by_df_name",
      "iso7816_read_binary",
      "iso7816_update_binary",
      "iso7816_read_records",
      "iso7816_append_record",
      "iso7816_get_challenge",
      "iso7816_authenticate",
      "raw_apdu",
      "raw_native"
    };

    bool valid_name(std::string_view value) noexcept {
      return !value.empty() && value.size() <= 64 && value.front() >= 'a' && value.front() <= 'z' &&
             std::all_of(value.begin(), value.end(), [](char character) {
               return (character >= 'a' && character <= 'z') ||
                      (character >= '0' && character <= '9') || character == '_';
             });
    }

    void require(
      bool condition,
      const std::string &message
    ) {
      if (!condition) {
        throw std::invalid_argument(message);
      }
    }

    void normalize_hex(std::string &value) {
      std::size_t output = 0;
      for (const auto character : value) {
        if (character == ' ' || character == '\t' || character == '\r' || character == '\n') {
          continue;
        }
        const auto digit = nibble(character);
        require(digit >= 0, "Hex input contains a non-hex character");
        constexpr char digits[] = "0123456789ABCDEF";
        value[output++] = digits[digit];
      }
      // Remove the unused tail only after overwriting it; it may still contain key bytes.
      for (std::size_t i = output; i < value.size(); ++i) {
        volatile auto *position = value.data() + i;
        *position = 0;
      }
      value.resize(output);
      require((value.size() & 1) == 0, "Hex input must contain complete bytes");
    }

    void validate_field(
      const field_spec &field,
      std::string &value
    ) {
      require(value.size() <= maximum_hex_size, "Argument is too long: " + field.name);
      require(valid_utf8(value), "Argument contains invalid text: " + field.name);
      if (field.type == "hex") {
        normalize_hex(value);
      }
      if (value.empty()) {
        require(!field.required, "Required argument: " + field.name);
        return;
      }
      if (field.type == "hex") {
        require(!field.width || value.size() == *field.width, "Invalid hex width: " + field.name);
      } else if (field.type == "number") {
        const auto parsed = decimal(value);
        require(
          parsed >= field.minimum && parsed <= field.maximum, "Argument out of range: " + field.name
        );
      } else if (field.type == "select") {
        require(
          std::find(field.options.begin(), field.options.end(), value) != field.options.end(),
          "Unknown choice: " + field.name
        );
      } else {
        require(
          value.size() <= 1024 && std::none_of(
                                    value.begin(),
                                    value.end(),
                                    [](unsigned char character) {
                                      return character < 32 || character == 127;
                                    }
                                  ),
          "Invalid or excessive text: " + field.name
        );
      }
    }

    void byte_bounds(
      const arguments &args,
      std::string_view field,
      std::size_t minimum,
      std::size_t maximum
    ) {
      const auto size = argument(args, field).size() / 2;
      require(size >= minimum && size <= maximum, "Invalid byte length: " + std::string(field));
    }

    void validate_relationships(const command_request &request) {
      const auto &name = request.spec->name;
      const auto &args = request.args;
      if (name == "credential_add") {
        validate_key(argument(args, "key"), argument(args, "key_type"));
      } else if (
        name == "authenticate" || name == "authenticate_iso" || name == "authenticate_aes" ||
        name == "iso7816_authenticate"
      ) {
        const auto type = name == "authenticate_aes" ? "aes_128" : argument(args, "key_type");
        if (argument(args, "credential_id").empty()) {
          validate_key(argument(args, "key"), type);
        } else {
          require(argument(args, "key").empty(), "Choose a saved credential or a direct key");
        }
        require(
          name != "authenticate" || type == "des" || type == "tdes_2k",
          "Native legacy authentication requires DES or two-key TDES"
        );
        require(
          name != "authenticate_iso" || type != "aes_128",
          "Native ISO authentication requires DES or TDES"
        );
      } else if (name == "change_picc_master_key") {
        validate_key(argument(args, "new_key"), argument(args, "key_type"));
      } else if (name == "change_app_key") {
        validate_key(argument(args, "old_key"), argument(args, "old_type"));
        validate_key(argument(args, "new_key"), argument(args, "new_type"));
        require(
          same_key_family(argument(args, "old_type"), argument(args, "new_type")),
          "Application key replacement must preserve the application key family"
        );
      } else if (name == "raw_apdu") {
        byte_bounds(args, "data", 4, 261);
      } else if (name == "raw_native") {
        byte_bounds(args, "data", 1, 256);
      } else if (name == "iso7816_update_binary" || name == "iso7816_append_record") {
        byte_bounds(args, "data", 1, 255);
      } else if (name == "iso7816_select_by_df_name") {
        byte_bounds(args, "name", 1, 16);
      } else if (name == "create_application") {
        require(hex_integer(args, "aid") != 0, "Application AID must be nonzero");
        const auto settings = hex_integer(args, "settings_2");
        const auto has_iso_id = !argument(args, "iso_id").empty();
        require(
          (settings & 15) <= 14 && (settings & 0xc0) != 0xc0,
          "Invalid application key count or key family"
        );
        require(
          ((settings & 0x20) != 0) == has_iso_id,
          "ISO identifier presence must match the application settings flag"
        );
        byte_bounds(args, "df_name", 0, 16);
        require(
          argument(args, "df_name").empty() || has_iso_id,
          "A DF name requires an ISO application identifier"
        );
      } else if (name == "delete_application") {
        require(hex_integer(args, "aid") != 0, "Application AID must be nonzero");
      } else if (name == "set_configuration") {
        const auto option = hex_integer(args, "option");
        require(
          option == 0 || option == 2 || option == 3, "Configuration option must be 00, 02, or 03"
        );
      } else if (name == "create_value_file") {
        const auto lower = decimal(argument(args, "lower_limit"));
        const auto upper = decimal(argument(args, "upper_limit"));
        const auto initial = decimal(argument(args, "initial_value"));
        require(
          lower <= upper && initial >= lower && initial <= upper,
          "Value limits must be ordered and contain the initial value"
        );
      } else if (name == "read_data") {
        const auto length = number(args, "length");
        require(
          static_cast<std::uint64_t>(number(args, "offset")) + length <= maximum_native_range,
          "Offset plus length exceeds the native range"
        );
        require(length <= maximum_response_size, "Requested response exceeds the session limit");
        require(
          argument(args, "mode") != "encrypted" || length != 0,
          "Encrypted reads require an explicit nonzero length"
        );
      } else if (name == "write_data" || name == "write_record") {
        require(
          static_cast<std::uint64_t>(number(args, "offset")) + argument(args, "data").size() / 2 <=
            maximum_native_range,
          "Offset plus data length exceeds the native range"
        );
      } else if (name == "read_records") {
        const auto count = number(args, "count");
        const auto total = static_cast<std::uint64_t>(count) * number(args, "record_size");
        require(
          static_cast<std::uint64_t>(number(args, "offset")) + count <= maximum_native_range,
          "First record plus count exceeds the native range"
        );
        require(total <= maximum_response_size, "Requested records exceed the session limit");
        require(
          argument(args, "mode") != "encrypted" || count != 0,
          "Encrypted record reads require an explicit nonzero count"
        );
      }
      if (name == "iso7816_read_binary" || name == "iso7816_update_binary") {
        require(
          argument(args, "short_file_id").empty() || number(args, "offset") <= 255,
          "Short file ID addressing requires an offset no greater than 255"
        );
      }
    }

    field_spec parse_field(const json &field) {
      field_spec output;
      output.name = field.at("name").get<std::string>();
      output.type = field.at("type").get<std::string>();
      require(valid_name(output.name), "Invalid catalog field name");
      require(
        output.type == "text" || output.type == "hex" || output.type == "number" ||
          output.type == "select",
        "Invalid catalog field type"
      );
      output.fallback = field.value("default", std::string{});
      output.required = field.value("required", output.type == "number" || output.type == "select");
      if (field.contains("width") && !field.at("width").is_null()) {
        require(
          field.at("width").is_number_unsigned() || field.at("width").is_number_integer(),
          "Invalid catalog hex width"
        );
        const auto width = field.at("width").get<std::int64_t>();
        require(
          width > 0 && width <= static_cast<std::int64_t>(maximum_hex_size) && width % 2 == 0,
          "Invalid catalog hex width"
        );
        output.width = static_cast<std::size_t>(width);
      }
      if (output.type == "number") {
        output.minimum = field.at("min").get<std::int64_t>();
        output.maximum = field.at("max").get<std::int64_t>();
        require(output.minimum <= output.maximum, "Invalid catalog numeric range");
      } else if (output.type == "select") {
        output.options = field.at("options").get<std::vector<std::string>>();
        require(!output.options.empty(), "Empty catalog choices");
      }
      require(
        !field.value("secret", false) || output.fallback.empty(),
        "Catalog must not contain default key material"
      );
      return output;
    }
  }

  command_catalog::command_catalog(const json &catalog) {
    try {
      require(catalog.is_object() && catalog.at("commands").is_array(), "Invalid command catalog");
      require(
        catalog.at("commands").size() == supported_commands.size(),
        "Command catalog must contain all supported commands"
      );
      for (const auto &entry : catalog.at("commands")) {
        command_spec spec;
        spec.name = entry.at("name").get<std::string>();
        spec.protocol = entry.at("protocol").get<std::string>();
        spec.mutating = entry.at("mutating").get<bool>();
        require(
          std::find(supported_commands.begin(), supported_commands.end(), spec.name) !=
            supported_commands.end(),
          "Unsupported catalog command"
        );
        require(
          spec.protocol == "native" || spec.protocol == "iso7816" || spec.protocol == "system" ||
            spec.protocol == "raw",
          "Invalid catalog protocol"
        );
        require(entry.at("fields").is_array(), "Invalid catalog fields");
        for (const auto &field : entry.at("fields")) {
          auto parsed = parse_field(field);
          require(
            std::none_of(
              spec.fields.begin(),
              spec.fields.end(),
              [&](const auto &existing) {
                return existing.name == parsed.name;
              }
            ),
            "Duplicate catalog field"
          );
          spec.fields.push_back(std::move(parsed));
        }
        const auto name = spec.name;
        require(commands_.emplace(name, std::move(spec)).second, "Duplicate catalog command");
      }
    } catch (const json::exception &) {
      throw std::invalid_argument("Invalid command catalog schema");
    }
  }

  void command_catalog::validate(
    const json &input,
    command_request &output
  ) const {
    require(input.is_object(), "Expected a command object");
    for (const auto &entry : input.items()) {
      require(
        entry.key() == "command" || entry.key() == "args" || entry.key() == "confirm" ||
          entry.key() == "expected_revision",
        "Unknown request property"
      );
    }
    require(
      input.contains("command") && input.at("command").is_string(), "Command must be a string"
    );
    const auto &name = input.at("command").get_ref<const std::string &>();
    const auto found = commands_.find(name);
    require(found != commands_.end(), "Unknown command");
    output.spec = &found->second;
    if (input.contains("expected_revision")) {
      const auto &revision = input.at("expected_revision");
      require(revision.is_string(), "Expected session revision must be a decimal string");
      const auto &value = revision.get_ref<const std::string &>();
      require(
        !value.empty() && value.size() <= 20 &&
          std::all_of(
            value.begin(),
            value.end(),
            [](char character) {
              return character >= '0' && character <= '9';
            }
          ),
        "Expected session revision must be a decimal string"
      );
      output.expected_revision = value;
    }
    require(
      !input.contains("confirm") || input.at("confirm").is_boolean(),
      "Confirmation must be a boolean"
    );
    if (
      (output.spec->mutating || output.spec->protocol == "raw") &&
      (!input.contains("confirm") || !input.at("confirm").get<bool>())
    ) {
      throw confirmation_required();
    }
    const auto supplied = input.find("args");
    if (supplied != input.end()) {
      require(supplied->is_object(), "Arguments must be an object");
      for (const auto &entry : supplied->items()) {
        require(
          std::any_of(
            output.spec->fields.begin(),
            output.spec->fields.end(),
            [&](const auto &field) {
              return field.name == entry.key();
            }
          ),
          "Unknown command argument"
        );
      }
    }
    for (const auto &field : output.spec->fields) {
      auto &value = output.args[field.name];
      if (supplied != input.end() && supplied->contains(field.name)) {
        const auto &source = supplied->at(field.name);
        if (source.is_string()) {
          const auto &text = source.get_ref<const std::string &>();
          require(text.size() <= maximum_hex_size, "Argument is too long: " + field.name);
          value = text;
        } else if (field.type == "number" && source.is_number_integer()) {
          if (source.is_number_unsigned()) {
            require(
              source.get<std::uint64_t>() <=
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()),
              "Decimal integer is out of range"
            );
          }
          value = std::to_string(source.get<std::int64_t>());
        } else {
          throw std::invalid_argument("Invalid argument type: " + field.name);
        }
      } else {
        value = field.fallback;
      }
      validate_field(field, value);
    }
    validate_relationships(output);
  }

  const std::string &argument(
    const arguments &args,
    std::string_view name
  ) {
    const auto found = args.find(name);
    if (found == args.end()) {
      throw std::invalid_argument("Missing command argument: " + std::string(name));
    }
    return found->second;
  }

  std::uint32_t number(
    const arguments &args,
    std::string_view name
  ) {
    return static_cast<std::uint32_t>(decimal(argument(args, name)));
  }

  std::uint32_t hex_integer(
    const arguments &args,
    std::string_view name
  ) {
    const auto &value = argument(args, name);
    require(value.size() <= 8, "Hexadecimal integer is out of range");
    std::uint32_t output = 0;
    for (const auto character : value) {
      const auto digit = nibble(character);
      require(digit >= 0, "Invalid hexadecimal integer");
      output = (output << 4) | static_cast<std::uint32_t>(digit);
    }
    return output;
  }

  desfire::communication_mode communication(const arguments &args) {
    const auto &mode = argument(args, "mode");
    if (mode == "plain") {
      return desfire::communication_mode::plain;
    }
    if (mode == "mac") {
      return desfire::communication_mode::mac;
    }
    return desfire::communication_mode::encrypted;
  }

  desfire::access_rights access(const arguments &args) {
    return {
      static_cast<std::uint8_t>(number(args, "read")),
      static_cast<std::uint8_t>(number(args, "write")),
      static_cast<std::uint8_t>(number(args, "read_write")),
      static_cast<std::uint8_t>(number(args, "change"))
    };
  }

  std::optional<std::uint16_t> optional_iso_id(const arguments &args) {
    if (argument(args, "iso_id").empty()) {
      return {};
    }
    return static_cast<std::uint16_t>(hex_integer(args, "iso_id"));
  }

  std::optional<std::uint8_t> short_id(const arguments &args) {
    if (argument(args, "short_file_id").empty()) {
      return {};
    }
    return static_cast<std::uint8_t>(number(args, "short_file_id"));
  }
}
