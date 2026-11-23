/// @file
/// @brief One explicitly managed physical card and ephemeral credential store.

#ifndef desfire_console_command_session_hpp
#define desfire_console_command_session_hpp

#include "../transport/pcsc_reader.hpp"
#include "command_arguments.hpp"
#include <memory>

namespace desfire_console::detail {
  struct credential final {
    std::string id;
    std::string name;
    std::string type;
    std::uint32_t aid{0};
    std::uint8_t number{0};
    std::uint8_t version{0};
    secret_bytes key;
  };

  struct authentication_metadata final {
    std::string protocol;
    std::string type;
    std::string credential_id;
    std::uint8_t number{0};
  };

  /// All methods require the enclosing service's external lock. No method retries I/O.
  /// Reader callbacks borrow this object; card_ is destroyed before reader_ and before this.
  /// Authentication and selection record only verified facts, never inferred follow-up work.
  class command_session final {
    std::unique_ptr<pcsc_reader> reader_;
    std::unique_ptr<desfire::card> card_;
    std::string reader_name_;
    std::optional<std::uint32_t> selected_aid_;
    std::optional<authentication_metadata> authenticated_;
    bool requires_reconnect_{false};
    bool native_called_{false};
    bool apdu_called_{false};
    std::uint64_t revision_{0};
    std::map<std::string, std::unique_ptr<credential>, std::less<>> credentials_;
    std::uint64_t next_credential_{1};

    void close() noexcept;
    void require_connected(bool typed = true) const;
    void validate_session(const command_request &request) const;
    desfire::exchange_callback observed_native();
    desfire::apdu_exchange_callback observed_apdu();
    json add_credential(const arguments &args);
    json authenticate(
      const std::string &command,
      const arguments &args
    );
    json select_native(const arguments &args);
    json raw(
      const std::string &command,
      const arguments &args
    );
    json execute_native(
      const std::string &command,
      const arguments &args
    );
    json execute_native_management(
      const std::string &command,
      const arguments &args
    );
    json execute_native_keys(
      const std::string &command,
      const arguments &args
    );
    json execute_native_files(
      const std::string &command,
      const arguments &args
    );
    json execute_native_data(
      const std::string &command,
      const arguments &args
    );
    json execute_iso(
      const std::string &command,
      const arguments &args
    );

    /// Publish a DF transition even when verified delivery precedes a local copy failure.
    template <class Function>
    json select_iso(
      bool changes_df,
      std::optional<std::uint32_t> aid,
      Function operation
    ) {
      try {
        auto value = take(operation());
        if (changes_df) {
          selected_aid_ = aid;
          authenticated_.reset();
        }
        return iso_payload(value);
      } catch (const operation_failure &failure) {
        if (changes_df && failure.error.outcome == desfire::delivery_outcome::succeeded) {
          selected_aid_ = aid;
          authenticated_.reset();
        }
        throw;
      }
    }

  public:

    ~command_session();
    void begin_request() noexcept;
    /// Bind an attempted card operation to the state reviewed by its caller. Rejection is local.
    void admit(const command_request &request);
    bool called_reader() const noexcept;
    json execute(const command_request &request);
    json state() const;
    json credentials() const;
    void apply_failure(
      const command_request &request,
      const desfire::operation_error &error
    );
    json error_response(
      const desfire::operation_error &error,
      const std::string &message,
      std::string_view code = {}
    ) const;
  };
}

#endif
