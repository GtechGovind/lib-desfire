/// @file
/// @brief Public command boundary and exception-to-envelope adaptation.

#include "command_service.hpp"
#include "command_session.hpp"
#include <stdexcept>

namespace desfire_console {
  class command_service::implementation final {
    detail::command_catalog catalog_;
    detail::command_session session_;

    nlohmann::json unexpected_failure(
      const detail::command_request &request,
      desfire::error_code code,
      const std::string &message,
      bool dispatched
    ) {
      const desfire::operation_error error{
        code,
        session_.called_reader() ? desfire::delivery_outcome::unknown
                                 : desfire::delivery_outcome::not_sent
      };
      if (dispatched) {
        session_.apply_failure(request, error);
      }
      return session_.error_response(error, message);
    }

  public:

    explicit implementation(const nlohmann::json &catalog) : catalog_(catalog) {}

    nlohmann::json execute(const nlohmann::json &request) {
      detail::command_request input;
      bool dispatched = false;
      session_.begin_request();
      try {
        catalog_.validate(request, input);
        session_.admit(input);
        dispatched = true;
        auto result = session_.execute(input);
        return {{"ok", true}, {"result", std::move(result)}, {"state", session_.state()}};
      } catch (const detail::confirmation_required &failure) {
        return session_.error_response(
          {desfire::error_code::invalid_argument}, failure.what(), "confirmation_required"
        );
      } catch (const detail::stale_session &failure) {
        return session_.error_response(
          {desfire::error_code::invalid_state}, failure.what(), "stale_session"
        );
      } catch (const detail::operation_failure &failure) {
        if (dispatched) {
          session_.apply_failure(input, failure.error);
        }
        return session_.error_response(failure.error, failure.message);
      } catch (const pcsc_exception &failure) {
        const desfire::operation_error error{
          desfire::error_code::transport_error,
          session_.called_reader() ? desfire::delivery_outcome::unknown
                                   : desfire::delivery_outcome::not_sent,
          {},
          failure.code()
        };
        session_.apply_failure(input, error);
        return session_.error_response(error, failure.what());
      } catch (const std::invalid_argument &failure) {
        if (session_.called_reader()) {
          return unexpected_failure(
            input, desfire::error_code::callback_failed, "Command operation failed", dispatched
          );
        }
        return session_.error_response(
          {desfire::error_code::invalid_argument}, failure.what(), "invalid_arguments"
        );
      } catch (const nlohmann::json::exception &) {
        if (dispatched) {
          return unexpected_failure(
            input,
            desfire::error_code::callback_failed,
            "Command result could not be constructed",
            dispatched
          );
        }
        return session_.error_response(
          {desfire::error_code::invalid_argument}, "Invalid request schema", "invalid_arguments"
        );
      } catch (const std::bad_alloc &) {
        return unexpected_failure(
          input, desfire::error_code::allocation_failed, "Memory allocation failed", dispatched
        );
      } catch (...) {
        return unexpected_failure(
          input, desfire::error_code::callback_failed, "Command operation failed", dispatched
        );
      }
    }

    nlohmann::json state() const { return session_.state(); }

    nlohmann::json credentials() const { return session_.credentials(); }
  };

  command_service::command_service(nlohmann::json catalog)
      : implementation_(std::make_unique<implementation>(catalog)) {}

  command_service::~command_service() = default;

  nlohmann::json command_service::execute(const nlohmann::json &request) {
    return implementation_->execute(request);
  }

  nlohmann::json command_service::state() const {
    return implementation_->state();
  }

  nlohmann::json command_service::credentials() const {
    return implementation_->credentials();
  }
}
