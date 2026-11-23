/// @file
/// @brief Connection, authentication and delivery-aware session metadata.

#include "command_session.hpp"
#include <chrono>
#include <limits>
#include <stdexcept>

namespace desfire_console::detail {
  command_session::~command_session() {
    close();
  }

  void command_session::close() noexcept {
    card_.reset();
    reader_.reset();
    reader_name_.clear();
    selected_aid_.reset();
    authenticated_.reset();
    requires_reconnect_ = false;
  }

  void command_session::begin_request() noexcept {
    native_called_ = false;
    apdu_called_ = false;
  }

  void command_session::admit(const command_request &request) {
    const auto &spec = *request.spec;
    const bool connection = spec.name == "connect" || spec.name == "disconnect";
    const bool card_command =
      spec.protocol == "native" || spec.protocol == "iso7816" || spec.protocol == "raw";
    if (!connection && !card_command) {
      return;
    }
    if (
      (card_command && !request.expected_revision) ||
      (request.expected_revision && *request.expected_revision != std::to_string(revision_))
    ) {
      throw stale_session();
    }
    if (revision_ == std::numeric_limits<std::uint64_t>::max()) {
      throw operation_failure(
        {desfire::error_code::invalid_state}, "Session revision limit reached; restart the service"
      );
    }
    ++revision_;
  }

  bool command_session::called_reader() const noexcept {
    return native_called_ || apdu_called_;
  }

  void command_session::require_connected(bool typed) const {
    if (!card_) {
      throw operation_failure({desfire::error_code::invalid_state}, "Connect a reader first");
    }
    if (typed && requires_reconnect_) {
      throw operation_failure(
        {desfire::error_code::invalid_state}, "Reconnect explicitly before using typed commands"
      );
    }
  }

  desfire::exchange_callback command_session::observed_native() {
    auto callback = reader_->exchange();
    return [this, callback = std::move(callback)](
             const std::uint8_t *data, std::size_t size, desfire::deadline deadline
           ) {
      native_called_ = true;
      return callback(data, size, deadline);
    };
  }

  desfire::apdu_exchange_callback command_session::observed_apdu() {
    auto callback = reader_->raw_exchange();
    return [this, callback = std::move(callback)](
             const std::uint8_t *data, std::size_t size, desfire::deadline deadline
           ) {
      apdu_called_ = true;
      return callback(data, size, deadline);
    };
  }

  json command_session::credentials() const {
    auto output = json::array();
    for (const auto &entry : credentials_) {
      const auto &value = *entry.second;
      output.push_back(
        {{"id", value.id},
         {"name", value.name},
         {"aid", hex_number(value.aid, 6)},
         {"number", value.number},
         {"key_type", value.type},
         {"version", hex_number(value.version, 2)}}
      );
    }
    return output;
  }

  json command_session::add_credential(const arguments &args) {
    if (
      credentials_.size() >= 128 || next_credential_ == std::numeric_limits<std::uint64_t>::max()
    ) {
      throw std::invalid_argument("Credential capacity reached");
    }
    auto value = std::make_unique<credential>();
    value->name = argument(args, "name");
    value->type = argument(args, "key_type");
    value->aid = hex_integer(args, "aid");
    value->number = static_cast<std::uint8_t>(number(args, "number"));
    value->version = static_cast<std::uint8_t>(hex_integer(args, "version"));
    value->key.value = unhex(argument(args, "key"));
    value->id = "key-" + std::to_string(next_credential_++);
    const auto id = value->id;
    credentials_.emplace(id, std::move(value));
    return {{"credentials", credentials()}, {"id", id}};
  }

  void command_session::validate_session(const command_request &request) const {
    const auto &name = request.spec->name;
    const auto &args = request.args;
    if (name == "format_picc" || name == "change_picc_master_key") {
      if (!selected_aid_ || *selected_aid_ != 0) {
        throw std::invalid_argument("Select PICC scope before changing the PICC");
      }
    }
    if (name == "change_app_key") {
      if (!selected_aid_ || *selected_aid_ == 0) {
        throw std::invalid_argument("Select an application AID before changing its key");
      }
      if (authenticated_ && !same_key_family(argument(args, "new_type"), authenticated_->type)) {
        throw std::invalid_argument(
          "Replacement key family must match the authenticated application"
        );
      }
    }
    if (
      authenticated_ && (name == "iso7816_read_binary" || name == "iso7816_read_records") &&
      number(args, "length") > 248
    ) {
      throw std::invalid_argument("Authenticated ISO reads allow at most 248 clear bytes");
    }
  }

  json command_session::authenticate(
    const std::string &command,
    const arguments &args
  ) {
    const auto selected_number = static_cast<std::uint8_t>(number(args, "number"));
    if (
      command == "iso7816_authenticate" && selected_aid_ && *selected_aid_ == 0 &&
      selected_number != 0
    ) {
      throw std::invalid_argument("ISO authentication in PICC scope requires key number zero");
    }
    const auto selected_type =
      command == "authenticate_aes" ? std::string("aes_128") : argument(args, "key_type");
    const auto &id = argument(args, "credential_id");
    const bytes *key = nullptr;
    secret_bytes supplied;
    if (!id.empty()) {
      const auto found = credentials_.find(id);
      if (found == credentials_.end()) {
        throw std::invalid_argument("Unknown credential ID");
      }
      const auto &saved = *found->second;
      if (!selected_aid_ || *selected_aid_ != saved.aid) {
        throw std::invalid_argument(
          "Select the saved credential's AID explicitly before authenticating"
        );
      }
      if (selected_number != saved.number || selected_type != saved.type) {
        throw std::invalid_argument("Key number and type must match the saved credential");
      }
      key = &saved.key.value;
    } else {
      supplied.value = unhex(argument(args, "key"));
      key = &supplied.value;
    }
    require_connected();
    authentication_metadata next{command, selected_type, id, selected_number};
    const bool had_authentication = authenticated_.has_value();
    try {
      if (command == "authenticate") {
        take(card_->authenticate(selected_number, key_type(selected_type), *key));
      } else if (command == "authenticate_iso") {
        take(card_->authenticate_iso(selected_number, key_type(selected_type), *key));
      } else if (command == "authenticate_aes") {
        take(card_->authenticate_aes(selected_number, *key));
      } else {
        take(card_->iso7816_authenticate(selected_number, key_type(selected_type), *key));
      }
      authenticated_ = std::move(next);
    } catch (const operation_failure &failure) {
      if (failure.error.outcome == desfire::delivery_outcome::succeeded) {
        authenticated_ = std::move(next);
      } else if (command != "iso7816_authenticate") {
        // Native authentication clears host credentials even if preparation did not send.
        authenticated_.reset();
        if (had_authentication && failure.error.outcome == desfire::delivery_outcome::not_sent) {
          requires_reconnect_ = true;
        }
      } else if (failure.error.outcome != desfire::delivery_outcome::not_sent) {
        authenticated_.reset();
      }
      throw;
    }
    return {{"authenticated", true}};
  }

  json command_session::select_native(const arguments &args) {
    const auto aid = hex_integer(args, "aid");
    const bool had_authentication = authenticated_.has_value();
    try {
      take(card_->select_application(aid));
      selected_aid_ = aid;
      authenticated_.reset();
    } catch (const operation_failure &failure) {
      // A valid native SELECT clears host authentication before preparation.
      authenticated_.reset();
      if (failure.error.outcome == desfire::delivery_outcome::succeeded) {
        selected_aid_ = aid;
      } else if (
        had_authentication && failure.error.outcome == desfire::delivery_outcome::not_sent
      ) {
        requires_reconnect_ = true;
      }
      throw;
    }
    return {{"aid", hex_number(aid, 6)}};
  }

  json command_session::raw(
    const std::string &command,
    const arguments &args
  ) {
    secret_bytes frame(unhex(argument(args, "data")));
    require_connected(false);
    auto callback = command == "raw_apdu" ? reader_->raw_exchange() : reader_->exchange();
    // Opaque raw transitions invalidate typed state even when delivery is subsequently rejected.
    requires_reconnect_ = true;
    authenticated_.reset();
    selected_aid_.reset();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    if (command == "raw_apdu") {
      apdu_called_ = true;
    } else {
      native_called_ = true;
    }
    secret_bytes response(take(callback(frame.value.data(), frame.value.size(), deadline)));
    const auto &value = response.value;
    const auto status_size = command == "raw_apdu" ? std::size_t{2} : std::size_t{1};
    if (value.size() < status_size) {
      throw operation_failure(
        {desfire::error_code::malformed_response, desfire::delivery_outcome::unknown}
      );
    }
    json output = {{"response", hex(value)}, {"length", value.size() - status_size}};
    if (command == "raw_apdu") {
      const auto size = value.size();
      const auto status = static_cast<std::uint32_t>(value[size - 2]) << 8 | value[size - 1];
      output["iso_status"] = hex_number(status, 4);
      output["data"] =
        hex(std::string_view(reinterpret_cast<const char *>(value.data()), size - 2));
    } else {
      output["card_status"] = hex_number(value.front(), 2);
      output["data"] =
        hex(std::string_view(reinterpret_cast<const char *>(value.data() + 1), value.size() - 1));
    }
    return output;
  }

  json command_session::execute(const command_request &request) {
    const auto &command = request.spec->name;
    const auto &args = request.args;
    if (command == "status") {
      return json::object();
    }
    if (command == "list_readers") {
      auto values = json::array();
      for (const auto &reader : list_readers()) {
        values.push_back(
          {{"name", reader.name}, {"card_present", reader.card_present}, {"atr", hex(reader.atr)}}
        );
      }
      return {{"readers", std::move(values)}};
    }
    if (command == "connect") {
      const auto name = choose_reader(list_readers(), argument(args, "reader"));
      close();
      auto reader = std::make_unique<pcsc_reader>(name, number(args, "wait_ms"));
      reader_ = std::move(reader);
      try {
        reader_name_ = name;
        card_ = std::make_unique<desfire::card>(
          observed_native(), observed_apdu(), desfire::card_options{}
        );
      } catch (...) {
        close();
        throw;
      }
      selected_aid_ = 0;
      return {{"connected", true}, {"library_version", desfire::card::get_library_version()}};
    }
    if (command == "disconnect") {
      close();
      return {{"connected", false}};
    }
    if (command == "credential_list") {
      return {{"credentials", credentials()}};
    }
    if (command == "credential_add") {
      return add_credential(args);
    }
    if (command == "credential_remove") {
      const auto found = credentials_.find(argument(args, "credential_id"));
      if (found == credentials_.end()) {
        throw std::invalid_argument("Unknown credential ID");
      }
      credentials_.erase(found);
      return {{"credentials", credentials()}};
    }
    if (request.spec->protocol == "raw") {
      return raw(command, args);
    }
    if (
      command == "authenticate" || command == "authenticate_iso" || command == "authenticate_aes" ||
      command == "iso7816_authenticate"
    ) {
      return authenticate(command, args);
    }
    require_connected();
    validate_session(request);
    if (request.spec->protocol == "native") {
      return execute_native(command, args);
    }
    if (request.spec->protocol == "iso7816") {
      return execute_iso(command, args);
    }
    throw operation_failure({desfire::error_code::unsupported}, "Unsupported command protocol");
  }

  void command_session::apply_failure(
    const command_request &request,
    const desfire::operation_error &error
  ) {
    if (!request.spec) {
      return;
    }
    const auto &command = request.spec->name;
    if (reader_ && reader_->requires_reconnect()) {
      requires_reconnect_ = true;
    }
    if (
      authenticated_ && error.outcome == desfire::delivery_outcome::not_sent &&
      request.spec->protocol == "native"
    ) {
      // Native preparation may discard/advance host credentials before its first callback.
      requires_reconnect_ = reader_ != nullptr;
      authenticated_.reset();
    }
    if (
      (command == "iso7816_update_binary" || command == "iso7816_append_record") &&
      error.outcome == desfire::delivery_outcome::rejected
    ) {
      authenticated_.reset();
    }
    if (error.outcome == desfire::delivery_outcome::unknown) {
      requires_reconnect_ = reader_ != nullptr;
      authenticated_.reset();
      if (command == "select_application" || command.rfind("iso7816_select_", 0) == 0) {
        selected_aid_.reset();
      }
    } else if (native_called_ && error.outcome != desfire::delivery_outcome::succeeded) {
      if (error.outcome == desfire::delivery_outcome::not_sent && authenticated_) {
        requires_reconnect_ = true;
      }
      authenticated_.reset();
    }
    if (error.outcome == desfire::delivery_outcome::succeeded) {
      if (command == "format_picc" || command == "change_picc_master_key") {
        authenticated_.reset();
      }
      if (
        command == "change_app_key" && authenticated_ &&
        authenticated_->number == number(request.args, "number")
      ) {
        authenticated_.reset();
      }
    } else if (
      error.outcome == desfire::delivery_outcome::not_sent && authenticated_ &&
      request.spec->protocol == "native" &&
      (error.code == desfire::error_code::allocation_failed ||
       error.code == desfire::error_code::callback_failed)
    ) {
      requires_reconnect_ = reader_ != nullptr;
      authenticated_.reset();
    }
  }

  json command_session::state() const {
    json authentication = nullptr;
    if (authenticated_) {
      authentication = {
        {"protocol", authenticated_->protocol},
        {"number", authenticated_->number},
        {"key_type", authenticated_->type},
        {"credential_id",
         authenticated_->credential_id.empty() ? json(nullptr)
                                               : json(authenticated_->credential_id)}
      };
    }
    return {
      {"connected", reader_ != nullptr},
      {"reader", reader_ ? json(reader_name_) : json(nullptr)},
      {"selected_aid", selected_aid_ ? json(hex_number(*selected_aid_, 6)) : json(nullptr)},
      {"authenticated", std::move(authentication)},
      {"requires_reconnect", requires_reconnect_},
      {"session_revision", std::to_string(revision_)},
      {"atr", reader_ ? hex(reader_->atr()) : std::string{}}
    };
  }

  json command_session::error_response(
    const desfire::operation_error &error,
    const std::string &message,
    std::string_view code
  ) const {
    return {
      {"ok", false},
      {"result", nullptr},
      {"state", state()},
      {"error",
       {{"code", code.empty() ? std::string(error_name(error.code)) : std::string(code)},
        {"error_code", error_name(error.code)},
        {"message", message.empty() ? error_name(error.code) : message},
        {"delivery", delivery_name(error.outcome)},
        {"card_status",
         error.card_status ? json(hex_number(*error.card_status, 2)) : json(nullptr)},
        {"iso_status", error.iso_status ? json(hex_number(*error.iso_status, 4)) : json(nullptr)},
        {"reader_error", error.transport_code ? json(*error.transport_code) : json(nullptr)}}}
    };
  }
}
