/// @file
/// @brief Windows contactless PC/SC reader ownership through a platform-neutral interface.

#ifndef desfire_console_pcsc_reader_hpp
#define desfire_console_pcsc_reader_hpp

#include <desfire/transport/apdu_callback.hpp>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace desfire_console {

  /// Reader enumeration result; no card connection or APDU is needed to obtain it.
  struct reader_info {
    std::string name;         ///< Exact UTF-8 PC/SC reader name.
    bool card_present{false}; ///< Presence reported by the PC/SC resource manager.
    desfire::bytes atr;       ///< Activation bytes, empty when no card is present.
  };

  /// Enumerate installed PC/SC readers and query their current card-presence state.
  /// @throws std::runtime_error Windows resource-manager or state-query failure.
  std::vector<reader_info> list_readers();

  /// Select only the exact requested reader name; there is no automatic reader choice.
  std::string choose_reader(
    const std::vector<reader_info> &readers,
    const std::string &requested
  );

  /// Preserve resource-manager failures separately from protocol delivery errors.
  class pcsc_exception : public std::runtime_error {
    int code_;

  public:

    pcsc_exception(
      const std::string &message,
      int code
    )
        : std::runtime_error(message),
          code_(code) {}

    int code() const noexcept { return code_; }
  };

  /// Own one exclusive card connection. Captured callbacks keep its state alive.
  /// Each callback sends once. A deadline expiry quarantines the connection while
  /// its worker finishes; no subsequent APDU is allowed. Closing resets the card.
  class pcsc_reader {
    /// Platform types and card lifetime remain private to the Windows implementation.
    struct session_state;
    /// Shared with any callback/worker that still needs the physical connection.
    std::shared_ptr<session_state> state_;

    /// Keep response decoding within the worker's admission/quarantine critical lifetime.
    desfire::exchange_callback exchange_impl(bool native) const;

  public:

    /// Wait up to wait_ms for insertion, then connect using the reader's T=0/T=1 protocol.
    explicit pcsc_reader(
      const std::string &name,
      std::uint32_t wait_ms
    );

    /// Release ownership; a pending transmission retains the connection until it finishes.
    ~pcsc_reader();

    /// Only callbacks may share the connection; the reader facade cannot be copied.
    pcsc_reader(const pcsc_reader &) = delete;
    /// Connection ownership cannot be replaced by assignment.
    pcsc_reader &operator=(const pcsc_reader &) = delete;

    /// Return a deadline-aware wrapped-native exchange callback for the public core API.
    desfire::exchange_callback exchange() const;

    /// Return untouched short APDU responses including SW1/SW2. Shares the native
    /// callback's single-send admission, worker ownership and timeout quarantine.
    /// Bind this callback and exchange() to the same SDK card to preserve its shared session.
    desfire::apdu_exchange_callback raw_exchange() const;

    /// Borrow the card's ATR captured at connection time.
    const desfire::bytes &atr() const noexcept;

    /// True once the deadline adapter has blocked further transmissions on this handle.
    bool requires_reconnect() const noexcept;
  };

} // namespace desfire_console

#endif
