/// @file
/// @brief Deadline worker adapter, independent of physical PC/SC devices.

#include "deadline_exchange.hpp"

#include <future>
#include <thread>

namespace desfire_console {
  namespace {
    /// One invocation's admission decision, shared by its caller and detached worker.
    struct admission_state {
      /// Serializes the timeout decision with the worker's final send-admission check.
      std::mutex mutex;
      /// Records that the worker crossed the send boundary before cancellation.
      bool started{false};
      /// Forbids a worker that has not yet crossed the boundary from sending later.
      bool cancelled{false};
    };
  }

  /// Serialize send admission with timeout; detached work owns all of its remaining resources.
  desfire::result<desfire::bytes> run_with_deadline(
    std::shared_ptr<deadline_exchange_state> state,
    desfire::deadline deadline,
    deadline_send send
  ) {
    using exchange_result = desfire::result<desfire::bytes>;
    if (!state || !send) {
      return exchange_result::failure({desfire::error_code::invalid_argument});
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      return exchange_result::failure({desfire::error_code::timeout});
    }

    auto admission = std::make_shared<admission_state>();
    auto promise = std::make_shared<std::promise<exchange_result>>();
    auto response = promise->get_future();
    {
      std::lock_guard<std::mutex> lock(state->mutex);
      if (state->quarantined) {
        return exchange_result::failure(
          {desfire::error_code::invalid_state, desfire::delivery_outcome::unknown}
        );
      }
      if (state->in_flight) {
        return exchange_result::failure({desfire::error_code::busy});
      }
      state->in_flight = true;
    }

    std::thread worker;
    try {
      worker = std::thread([state, admission, promise, deadline, send = std::move(send)]() {
        auto result = exchange_result::failure({desfire::error_code::timeout});
        bool admitted = false;
        try {
          {
            std::lock_guard<std::mutex> lock(admission->mutex);
            if (!admission->cancelled && std::chrono::steady_clock::now() < deadline) {
              admission->started = true;
              admitted = true;
            }
          }
          if (admitted) {
            result = send();
            if (std::chrono::steady_clock::now() >= deadline) {
              result = exchange_result::failure(
                {desfire::error_code::timeout, desfire::delivery_outcome::unknown}
              );
            }
          }
        } catch (...) {
          result = exchange_result::failure(
            {desfire::error_code::callback_failed,
             admitted ? desfire::delivery_outcome::unknown : desfire::delivery_outcome::not_sent}
          );
        }
        {
          std::lock_guard<std::mutex> lock(state->mutex);
          state->quarantined = state->quarantined || !result;
          state->in_flight = false;
        }
        promise->set_value(std::move(result));
      });
    } catch (...) {
      // A thread that could not be created never passed the send-admission boundary.
      std::lock_guard<std::mutex> lock(state->mutex);
      state->in_flight = false;
      return exchange_result::failure({desfire::error_code::callback_failed});
    }

    if (response.wait_until(deadline) != std::future_status::ready) {
      bool started = false;
      {
        std::lock_guard<std::mutex> lock(admission->mutex);
        admission->cancelled = true;
        started = admission->started;
        std::lock_guard<std::mutex> session_lock(state->mutex);
        state->quarantined = true;
      }
      worker.detach();
      return exchange_result::failure(
        {desfire::error_code::timeout,
         started ? desfire::delivery_outcome::unknown : desfire::delivery_outcome::not_sent}
      );
    }
    worker.join();
    return response.get();
  }
}
