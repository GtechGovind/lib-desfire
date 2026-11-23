/// @file
/// @brief Typed native commands with explicit, delivery-aware state transitions.

#include "command_session.hpp"

namespace desfire_console::detail {
  namespace {
    json read_payload(desfire::result<bytes> result) {
      secret_bytes value(take(std::move(result)));
      return payload(value.value);
    }
  }

  json command_session::execute_native_management(
    const std::string &command,
    const arguments &args
  ) {
    if (command == "init") {
      const bool had_authentication = authenticated_.has_value();
      take(card_->init());
      authenticated_.reset();
      // Resetting only host authentication leaves the card's cipher state unrecoverable here.
      if (had_authentication) {
        requires_reconnect_ = true;
      }
      return json::object();
    }
    if (command == "get_version") {
      const auto value = take(card_->get_version());
      return {
        {"hardware", hex(value.hardware)},
        {"software", hex(value.software)},
        {"uid", hex(value.uid)},
        {"batch", hex(value.batch)},
        {"production_week", hex_number(value.production_week, 2)},
        {"production_year", hex_number(value.production_year, 2)}
      };
    }
    if (command == "free_memory") {
      return {{"free_memory", take(card_->free_memory())}};
    }
    if (command == "get_card_uid") {
      return read_payload(card_->get_card_uid());
    }
    if (command == "get_application_ids") {
      auto values = json::array();
      for (const auto value : take(card_->get_application_ids())) {
        values.push_back(hex_number(value, 6));
      }
      return {{"application_ids", std::move(values)}};
    }
    if (command == "get_df_names") {
      auto values = json::array();
      for (const auto &value : take(card_->get_df_names())) {
        values.push_back(
          {{"aid", hex_number(value.application_id, 6)},
           {"iso_id", hex_number(value.iso_id, 4)},
           {"name", hex(value.name)}}
        );
      }
      return {{"df_names", std::move(values)}};
    }
    if (command == "get_fids") {
      auto values = json::array();
      for (const auto value : take(card_->get_fids())) {
        values.push_back(value);
      }
      return {{"file_ids", std::move(values)}};
    }
    if (command == "get_iso_fids") {
      auto values = json::array();
      for (const auto value : take(card_->get_iso_fids())) {
        values.push_back(hex_number(value, 4));
      }
      return {{"iso_file_ids", std::move(values)}};
    }
    if (command == "get_key_settings") {
      const auto value = take(card_->get_key_settings());
      return {
        {"settings_1", hex_number(value.settings_1, 2)},
        {"settings_2", hex_number(value.settings_2, 2)}
      };
    }
    if (command == "select_application") {
      return select_native(args);
    }
    if (command == "create_application") {
      desfire::application_config config;
      config.id = hex_integer(args, "aid");
      config.keys = {
        static_cast<std::uint8_t>(hex_integer(args, "settings_1")),
        static_cast<std::uint8_t>(hex_integer(args, "settings_2"))
      };
      config.iso_id = optional_iso_id(args);
      secret_bytes name(unhex(argument(args, "df_name")));
      if (name.value.empty()) {
        take(card_->create_application(config));
      } else {
        take(card_->create_application(config, name.value));
      }
      return json::object();
    }
    if (command == "delete_application") {
      take(card_->delete_application(hex_integer(args, "aid")));
      return json::object();
    }
    if (command == "format_picc") {
      take(card_->format_picc());
      authenticated_.reset();
      return json::object();
    }
    if (command == "set_configuration") {
      secret_bytes data(unhex(argument(args, "data")));
      take(
        card_->set_configuration(static_cast<std::uint8_t>(hex_integer(args, "option")), data.value)
      );
      return json::object();
    }
    throw operation_failure(
      {desfire::error_code::unsupported}, "Unsupported native management command"
    );
  }

  json command_session::execute_native_keys(
    const std::string &command,
    const arguments &args
  ) {
    if (command == "get_key_version") {
      const auto value =
        take(card_->get_key_version(static_cast<std::uint8_t>(number(args, "number"))));
      return {{"version", hex_number(value, 2)}};
    }
    if (command == "change_key_settings") {
      take(card_->change_key_settings(static_cast<std::uint8_t>(hex_integer(args, "settings"))));
      return json::object();
    }
    if (command == "change_picc_master_key") {
      secret_bytes key(unhex(argument(args, "new_key")));
      take(card_->change_picc_master_key(
        key_type(argument(args, "key_type")),
        key.value,
        static_cast<std::uint8_t>(hex_integer(args, "version"))
      ));
      authenticated_.reset();
      return json::object();
    }
    if (command == "change_app_key") {
      secret_bytes old_key(unhex(argument(args, "old_key")));
      secret_bytes new_key(unhex(argument(args, "new_key")));
      const auto key_number = static_cast<std::uint8_t>(number(args, "number"));
      take(card_->change_app_key(
        key_number,
        key_type(argument(args, "old_type")),
        old_key.value,
        key_type(argument(args, "new_type")),
        new_key.value,
        static_cast<std::uint8_t>(hex_integer(args, "version"))
      ));
      if (authenticated_ && authenticated_->number == key_number) {
        authenticated_.reset();
      }
      return json::object();
    }
    throw operation_failure({desfire::error_code::unsupported}, "Unsupported native key command");
  }

  json command_session::execute_native_files(
    const std::string &command,
    const arguments &args
  ) {
    if (command == "get_file_settings") {
      return file_json(
        take(card_->get_file_settings(static_cast<std::uint8_t>(number(args, "file"))))
      );
    }
    if (command == "change_file_settings") {
      const desfire::file_settings_change config{
        communication(args), access(args), argument(args, "encrypted_command") == "true"
      };
      take(card_->change_file_settings(static_cast<std::uint8_t>(number(args, "file")), config));
      return json::object();
    }
    if (command == "create_std_data_file" || command == "create_backup_data_file") {
      const desfire::data_file_config config{
        communication(args), access(args), number(args, "size"), optional_iso_id(args)
      };
      const auto file = static_cast<std::uint8_t>(number(args, "file"));
      if (command == "create_std_data_file") {
        take(card_->create_std_data_file(file, config));
      } else {
        take(card_->create_backup_data_file(file, config));
      }
      return json::object();
    }
    if (command == "create_value_file") {
      const desfire::value_file_config config{
        communication(args),
        access(args),
        static_cast<std::int32_t>(decimal(argument(args, "lower_limit"))),
        static_cast<std::int32_t>(decimal(argument(args, "upper_limit"))),
        static_cast<std::int32_t>(decimal(argument(args, "initial_value"))),
        argument(args, "limited_credit_enabled") == "true"
      };
      take(card_->create_value_file(static_cast<std::uint8_t>(number(args, "file")), config));
      return json::object();
    }
    if (command == "create_linear_record_file" || command == "create_cyclic_record_file") {
      const desfire::record_file_config config{
        communication(args),
        access(args),
        number(args, "record_size"),
        number(args, "max_records"),
        optional_iso_id(args)
      };
      const auto file = static_cast<std::uint8_t>(number(args, "file"));
      if (command == "create_linear_record_file") {
        take(card_->create_linear_record_file(file, config));
      } else {
        take(card_->create_cyclic_record_file(file, config));
      }
      return json::object();
    }
    if (command == "delete_file") {
      take(card_->delete_file(static_cast<std::uint8_t>(number(args, "file"))));
      return json::object();
    }
    throw operation_failure({desfire::error_code::unsupported}, "Unsupported native file command");
  }

  json command_session::execute_native_data(
    const std::string &command,
    const arguments &args
  ) {
    if (command == "read_data") {
      return read_payload(card_->read_data(
        static_cast<std::uint8_t>(number(args, "file")),
        communication(args),
        number(args, "offset"),
        number(args, "length")
      ));
    }
    if (command == "write_data" || command == "write_record") {
      secret_bytes data(unhex(argument(args, "data")));
      const auto file = static_cast<std::uint8_t>(number(args, "file"));
      const auto mode = communication(args);
      const auto offset = number(args, "offset");
      if (command == "write_data") {
        take(card_->write_data(file, mode, offset, data.value));
      } else {
        take(card_->write_record(file, mode, offset, data.value));
      }
      return json::object();
    }
    if (command == "get_value") {
      return {
        {"value",
         take(
           card_->get_value(static_cast<std::uint8_t>(number(args, "file")), communication(args))
         )}
      };
    }
    if (command == "credit" || command == "debit" || command == "limited_credit") {
      const auto file = static_cast<std::uint8_t>(number(args, "file"));
      const auto mode = communication(args);
      const auto amount = static_cast<std::int32_t>(number(args, "amount"));
      if (command == "credit") {
        take(card_->credit(file, mode, amount));
      } else if (command == "debit") {
        take(card_->debit(file, mode, amount));
      } else {
        take(card_->limited_credit(file, mode, amount));
      }
      return json::object();
    }
    if (command == "read_records") {
      return read_payload(card_->read_records(
        static_cast<std::uint8_t>(number(args, "file")),
        communication(args),
        number(args, "offset"),
        number(args, "count"),
        number(args, "record_size")
      ));
    }
    if (command == "clear_record_file") {
      take(card_->clear_record_file(static_cast<std::uint8_t>(number(args, "file"))));
      return json::object();
    }
    if (command == "commit_transaction") {
      take(card_->commit_transaction());
      return json::object();
    }
    if (command == "abort_transaction") {
      take(card_->abort_transaction());
      return json::object();
    }
    throw operation_failure({desfire::error_code::unsupported}, "Unsupported native command");
  }

  json command_session::execute_native(
    const std::string &command,
    const arguments &args
  ) {
    if (
      command == "get_key_version" || command == "change_key_settings" ||
      command == "change_picc_master_key" || command == "change_app_key"
    ) {
      return execute_native_keys(command, args);
    }
    if (
      command == "get_file_settings" || command == "change_file_settings" ||
      command == "create_std_data_file" || command == "create_backup_data_file" ||
      command == "create_value_file" || command == "create_linear_record_file" ||
      command == "create_cyclic_record_file" || command == "delete_file"
    ) {
      return execute_native_files(command, args);
    }
    if (
      command == "read_data" || command == "write_data" || command == "get_value" ||
      command == "credit" || command == "debit" || command == "limited_credit" ||
      command == "read_records" || command == "write_record" || command == "clear_record_file" ||
      command == "commit_transaction" || command == "abort_transaction"
    ) {
      return execute_native_data(command, args);
    }
    return execute_native_management(command, args);
  }
}
