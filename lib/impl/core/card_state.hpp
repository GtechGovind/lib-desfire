#pragma once

#include "../crypto/openssl_crypto.hpp"
#include "../session/selection.hpp"
#include "../session/session.hpp"
#include <atomic>
#include <desfire/card.hpp>

namespace desfire::detail {

  /// Mutable state for one reader/card connection. Access requires operation admission,
  /// except immutable options, which buffer adapters may inspect before admission.
  struct card_state {

    /// Synchronous native-frame adapter; invoked only while the operation lock is held.
    exchange_callback exchange;

    /// Complete standard APDU adapter for the same physical card activation.
    apdu_exchange_callback apdu_exchange;

    /// Construction-time limits shared by all command and authentication exchanges.
    const card_options options;
    /// Nonblocking admission also rejects same-thread callback reentry without mutex recursion.
    std::atomic_flag operation_active = ATOMIC_FLAG_INIT;
    /// Live key, cipher family and retained IV for the selected physical card/application.
    session_state session;

    /// Lazily created provider context; plain unauthenticated commands do not need it.
    std::shared_ptr<crypto_context> crypto;

    /// Selection of both protocol namespaces. Local authentication reset cannot change it.
    selection_state selection;

    /// Uncertain transport or integrity failure requires an explicit local reset.
    bool poisoned{false};

    /// Tracks whether any frame in the admitted operation may have reached the card.
    bool transmitted{false};

    /// Verified physical frame boundaries retained for GetDFNames record parsing.
    std::vector<bytes> response_frames;

    /// Take ownership of the adapter and copy immutable limits; validation occurs on admission.
    card_state(
      exchange_callback callback,
      const card_options &limits,
      apdu_exchange_callback apdu_callback = {}
    )
        : exchange(std::move(callback)),
          apdu_exchange(std::move(apdu_callback)),
          options(limits) {}
  };

  /// Validate the adapter and all limits before allocating or sending an operation.
  [[nodiscard]] bool validate_card_options(const card_state &state) noexcept;

  /// Validate shared timeout/clear payload bounds and the limits of complete raw APDUs.
  [[nodiscard]] bool validate_iso7816_options(const card_state &state) noexcept;

} // namespace desfire::detail
