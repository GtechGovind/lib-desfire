/// @file
/// @brief Single-send admission and lifetime control around a blocking reader call.

#ifndef desfire_console_deadline_exchange_hpp
#define desfire_console_deadline_exchange_hpp

#include <desfire/transport/callback.hpp>

#include <functional>
#include <memory>
#include <mutex>

namespace desfire_console {
  /// State shared by every callback using one physical reader connection.
  struct deadline_exchange_state {
    /// Protects both flags; callers must hold this mutex before accessing them.
    std::mutex mutex;
    /// Prevents all later sends after a failed exchange or an elapsed deadline.
    bool quarantined{false};
    /// Reserves the connection until the admitted worker has completely finished.
    bool in_flight{false};
  };

  /// Blocking operation owning its request bytes and reader resources through its captures.
  using deadline_send = std::function<desfire::result<desfire::bytes>()>;

  /// Send at most once, or cancel admission if the shared absolute deadline expires first.
  /// A running send retains its captures after timeout and quarantines the connection.
  desfire::result<desfire::bytes> run_with_deadline(
    std::shared_ptr<deadline_exchange_state> state,
    desfire::deadline deadline,
    deadline_send send
  );
}

#endif // desfire_console_deadline_exchange_hpp
