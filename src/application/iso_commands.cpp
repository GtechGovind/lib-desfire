/// @file
/// @brief ISO selection, bounded file commands and explicit challenge operations.

#include "command_session.hpp"

namespace desfire_console::detail {
  json command_session::execute_iso(
    const std::string &command,
    const arguments &args
  ) {
    if (
      command == "iso7816_select_master_file" || command == "iso7816_select_file" ||
      command == "iso7816_select_by_df_name"
    ) {
      const auto response = argument(args, "response") == "none"
                              ? desfire::iso7816_select_response::none
                              : desfire::iso7816_select_response::fci;
      if (command == "iso7816_select_master_file") {
        return select_iso(true, 0, [&] {
          return card_->iso7816_select_master_file(response);
        });
      }
      if (command == "iso7816_select_file") {
        const auto scope = argument(args, "scope") == "application_df"
                             ? desfire::iso7816_file_scope::application_df
                             : desfire::iso7816_file_scope::elementary_file;
        const auto identifier = static_cast<std::uint16_t>(hex_integer(args, "identifier"));
        return select_iso(scope == desfire::iso7816_file_scope::application_df, {}, [&] {
          return card_->iso7816_select_file(identifier, scope, response);
        });
      }
      secret_bytes name(unhex(argument(args, "name")));
      const bool master = argument(args, "name") == "D2760000850100";
      return select_iso(true, master ? std::optional<std::uint32_t>{0} : std::nullopt, [&] {
        return card_->iso7816_select_by_df_name(name.value, response);
      });
    }
    if (command == "iso7816_read_binary") {
      const desfire::iso7816_binary_read value{
        {static_cast<std::uint16_t>(number(args, "offset")), short_id(args)},
        static_cast<std::uint16_t>(number(args, "length"))
      };
      return iso_payload(take(card_->iso7816_read_binary(value)));
    }
    if (command == "iso7816_update_binary") {
      const desfire::iso7816_binary_address address{
        static_cast<std::uint16_t>(number(args, "offset")), short_id(args)
      };
      secret_bytes data(unhex(argument(args, "data")));
      take(card_->iso7816_update_binary(address, data.value));
      return {{"iso_status", "9000"}};
    }
    if (command == "iso7816_read_records") {
      const desfire::iso7816_record_read value{
        {short_id(args)},
        static_cast<std::uint8_t>(number(args, "record_number")),
        argument(args, "record_mode") == "absolute" ? desfire::iso7816_record_mode::absolute
                                                    : desfire::iso7816_record_mode::forward,
        static_cast<std::uint16_t>(number(args, "length"))
      };
      return iso_payload(take(card_->iso7816_read_records(value)));
    }
    if (command == "iso7816_append_record") {
      secret_bytes data(unhex(argument(args, "data")));
      take(
        card_->iso7816_append_record(desfire::iso7816_record_address{short_id(args)}, data.value)
      );
      return {{"iso_status", "9000"}};
    }
    if (command == "iso7816_get_challenge") {
      try {
        secret_bytes value(
          take(card_->iso7816_get_challenge(key_type(argument(args, "key_type"))))
        );
        authenticated_.reset();
        return payload(value.value);
      } catch (const operation_failure &failure) {
        if (apdu_called_ && failure.error.outcome != desfire::delivery_outcome::not_sent) {
          authenticated_.reset();
        }
        throw;
      }
    }
    throw operation_failure({desfire::error_code::unsupported}, "Unsupported ISO command");
  }
}
