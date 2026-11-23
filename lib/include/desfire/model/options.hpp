/// @file
/// @brief Per-card limits applied across a complete synchronous operation.

#ifndef desfire_desfire_model_options_hpp
#define desfire_desfire_model_options_hpp
#include <chrono>
#include <cstddef>

namespace desfire {
  /// Options copied by card construction and thereafter immutable within that instance.
  /// Before reader I/O, each admitted exchange validates the shared limits and the limits for
  /// its protocol. Invalid limits return invalid_argument. Generic range and capacity checks
  /// can report their own failures before admission. The local reset requires admission only.
  struct card_options {
    /// Steady-clock budget from admission through command preparation, all frames and verification.
    /// It must be positive and at most 24 hours. Input normalization and final output copying
    /// occur outside that budget. The callback must honor the supplied absolute deadline because
    /// the core cannot preempt blocking I/O.
    std::chrono::milliseconds operation_timeout{5000};
    /// Native transmit-frame byte limit, including opcode or AF prefix; valid range is 2..0xFFFFFF.
    /// Fixed commands must fit one frame. Writes need an eight-byte initial header, and
    /// authentication needs a complete 17-byte (DES/2K) or 33-byte (3K/AES) proof frame.
    std::size_t max_frame_size{60};
    /// Maximum total clear response size for either protocol, in bytes. It also bounds
    /// variable-length native write and configuration inputs. Valid range is 1..0xFFFFFF.
    /// Static keys and DF names have separate fixed limits.
    /// Bounded protection overhead is allowed separately while accumulating an encoded response.
    std::size_t max_response_size{8192};
    /// Additional upload/download frame budget; valid range is 1..0xFFFFFF.
    std::size_t max_additional_frames{1024};
    /// Inclusive size of a complete command APDU, valid range 4..261.
    std::size_t max_apdu_size{261};
    /// Inclusive size of an individual response APDU, valid range 2..258.
    std::size_t max_iso_response_size{258};
    /// Budget for standard GET RESPONSE exchanges, independent of native AF. Range is 1..0xFFFFFF.
    std::size_t max_iso_continuations{16};
  };
} // namespace desfire

#endif // desfire_desfire_model_options_hpp
