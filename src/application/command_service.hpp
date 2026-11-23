/// @file
/// @brief In-process, catalog-validated access to one DESFire reader session.

#ifndef desfire_console_command_service_hpp
#define desfire_console_command_service_hpp

#include <memory>
#include <nlohmann/json.hpp>

namespace desfire_console {

  /// Own a reader, its shared native/ISO card state, and ephemeral credentials.
  /// The caller must serialize every method, including metadata snapshots. There is no
  /// background work, automatic selection, authentication, retry, or reconnect here.
  class command_service final {
    class implementation;
    std::unique_ptr<implementation> implementation_;

  public:

    /// Validate and retain the command catalog. Construction performs no reader I/O.
    /// @throws std::invalid_argument If the catalog has an invalid schema.
    explicit command_service(nlohmann::json catalog);
    /// Close the card connection and erase owned credential bytes.
    ~command_service();

    command_service(const command_service &) = delete;
    command_service &operator=(const command_service &) = delete;

    /// Execute {command, args?, confirm?, expected_revision?} after complete local validation.
    /// Mutating and raw commands require confirm=true. Arguments have catalog defaults;
    /// hex accepts ASCII whitespace, and numeric fields accept integers or decimal strings.
    /// Every native, ISO and raw request must supply the decimal session_revision it reviewed.
    /// Matching card and connection attempts advance that revision, even on subsequent failure.
    /// Connect/disconnect may omit it for explicit recovery; stale requests never reach the reader.
    /// Return {ok, result, state, error?}; protocol failures include delivery information.
    /// Allocation failure while constructing the error envelope can still propagate.
    nlohmann::json execute(const nlohmann::json &request);
    /// Copy the last known session metadata without reader I/O.
    nlohmann::json state() const;
    /// Copy credential metadata as an array; key material is never included.
    nlohmann::json credentials() const;
  };
}

#endif
