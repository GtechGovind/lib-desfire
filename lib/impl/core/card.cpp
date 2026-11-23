/// @file
/// @brief Own a physical-card session and implement local lifecycle operations without reader I/O.

#include "card_state.hpp"
#include "operation.hpp"

namespace desfire {

  /// Allocate independent protocol state and take ownership of the synchronous adapter.
  /// Options are copied and validated when an operation is admitted. Construction sends no frame;
  /// allocation failure propagates because no result object exists yet.
  card::card(
    exchange_callback exchange,
    card_options options
  )
      : state_(
          std::make_unique<detail::card_state>(
            std::move(exchange),
            options
          )
        ) {}

  /// Move both protocol adapters into one owned card state and copy its immutable limits.
  /// Allocation precedes admission and may throw std::bad_alloc. Construction sends no frame.
  card::card(
    exchange_callback native_exchange,
    apdu_exchange_callback apdu_exchange,
    card_options options
  )
      : state_(
          std::make_unique<detail::card_state>(
            std::move(native_exchange),
            options,
            std::move(apdu_exchange)
          )
        ) {}

  /// Release both adapters and the provider context. Owned destructors erase the live session key.
  /// Physical selection and pending card transactions are unaffected by host destruction.
  card::~card() = default;

  /// Borrow the mutable session for a nonconst facade call; this accessor does not admit I/O.
  /// The caller must acquire operation_guard before touching shared mutable protocol state.
  //noinspection CppMemberFunctionMayBeConst
  // ReSharper disable once CppMemberFunctionMayBeConst
  detail::card_state &card::mutable_state() noexcept {
    return *state_;
  }

  /// Read the immutable variable-input bound without acquiring mutable session admission.
  /// Generic adapters use this before admission; fixed-size keys/names have narrower limits.
  std::size_t card::max_input_size() const noexcept {
    return state_->options.max_response_size;
  }

  /// Return a static-lifetime version string; querying it does not allocate or contact a card.
  std::string_view card::get_library_version() noexcept {
    return "0.2.0";
  }

  /// Erase local authentication and uncertainty under admission, retaining the last known AID.
  /// Recovery requires the caller to establish physical card state separately. This operation
  /// never selects an application or decides whether a prior mutation executed.
  result<void> card::init() {
    auto &state = mutable_state();
    const detail::operation_guard lock(state.operation_active);
    if (!lock.owns_lock()) {
      return result<void>::failure({error_code::busy});
    }
    // Local recovery requires admission only. Reader callbacks and wire limits apply to I/O.
    detail::clear_session(state.session);
    state.poisoned = false;
    state.transmitted = false;
    state.response_frames.clear();
    return result<void>::success();
  }

  namespace detail {

    /// Validate the shared timeout and clear response bounds for either protocol.
    static bool validate_common_limits(const card_options &options) noexcept {
      return options.operation_timeout.count() > 0 &&
             options.operation_timeout <= std::chrono::hours(24) && options.max_response_size > 0 &&
             options.max_response_size <= 0xffffff;
    }

    /// Validate complete APDU limits without inspecting any native framing options.
    bool validate_iso7816_options(const card_state &state) noexcept {
      const auto &options = state.options;
      return validate_common_limits(options) && options.max_apdu_size >= 4 &&
             options.max_apdu_size <= 261 && options.max_iso_response_size >= 2 &&
             options.max_iso_response_size <= 258 && options.max_iso_continuations > 0 &&
             options.max_iso_continuations <= 0xffffff;
    }

    /// Validate the adapter, positive bounded timeout, native 24-bit limits and AF budget.
    /// This pure check runs before operation deadline arithmetic, provider creation or reader I/O.
    bool validate_card_options(const card_state &state) noexcept {
      return static_cast<bool>(state.exchange) && validate_common_limits(state.options) &&
             state.options.max_frame_size >= 2 && state.options.max_frame_size <= 0xffffff &&
             state.options.max_additional_frames > 0 &&
             state.options.max_additional_frames <= 0xffffff;
    }

  } // namespace detail
} // namespace desfire
