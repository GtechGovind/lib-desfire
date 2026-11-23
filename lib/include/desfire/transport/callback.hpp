/// @file
/// @brief Caller-supplied synchronous reader exchange and its shared absolute deadline.

#ifndef desfire_desfire_transport_callback_hpp
#define desfire_desfire_transport_callback_hpp
#include "../buffer/byte_view.hpp"
#include "../common/result.hpp"
#include <chrono>
#include <functional>

namespace desfire {
  /// Monotonic absolute deadline; one value is shared by all frames of an operation.
  using deadline = std::chrono::steady_clock::time_point;
  /// Send one native frame exactly once and return an owned, complete status-first native reply.
  /// The arguments are a borrowed request pointer, its byte count and the operation's absolute
  /// steady-clock deadline. Consume the request before returning and honor that deadline in I/O.
  /// Adapt reader/APDU framing outside the core; never retry, reactivate or switch cards here.
  /// A failed result reports not_sent only when no frame left the reader, rejected only for a
  /// definite card rejection, and unknown when delivery/completion cannot be established.
  /// Captured reader resources must outlive card; thrown exceptions become unknown after send
  /// admission. Native rejection statuses may instead be returned normally as status-first bytes.
  using exchange_callback =
    std::function<result<bytes>(const std::uint8_t *, std::size_t, deadline)>;
} // namespace desfire

#endif // desfire_desfire_transport_callback_hpp
