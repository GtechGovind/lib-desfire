/// @file
/// @brief Owning success-or-error values used by synchronous card operations.

#ifndef desfire_desfire_common_result_hpp
#define desfire_desfire_common_result_hpp
#include "error.hpp"
#include <stdexcept>
#include <utility>
#include <variant>

namespace desfire {
  /// Own a success value or failure detail; accessors normally borrow from this result.
  /// @tparam value_type Stored object type; copying/moving follows its semantics and exceptions.
  /// A throwing assignment can discard both alternatives. Such a result reports invalid_state
  /// without retained delivery evidence until it is reassigned.
  template <class value_type> class result {
    /// Index zero is success even when value_type itself is operation_error.
    std::variant<value_type, operation_error> storage_;

    /// Construct the success alternative without using the payload's type to discriminate it.
    explicit result(
      std::in_place_index_t<0>,
      value_type value
    )
        : storage_(
            std::in_place_index<0>,
            std::move(value)
          ) {}

    /// Construct failure independently of the success payload type.
    explicit result(
      std::in_place_index_t<1>,
      const operation_error &error
    )
        : storage_(
            std::in_place_index<1>,
            error
          ) {}

  public:

    /// Store a success value by move; does not retain references to the argument.
    static result success(value_type value) {
      return result(std::in_place_index<0>, std::move(value));
    }

    /// Store a copy of the failure detail without constructing a success value.
    static result failure(const operation_error &error) {
      return result(std::in_place_index<1>, error);
    }

    /// Return whether the success alternative is active.
    [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }

    /// Test success in a condition without accessing either alternative.
    explicit operator bool() const noexcept { return has_value(); }

    /// Borrow the stored value for modification; throws std::logic_error on failure.
    /// The reference expires when this result is destroyed or its alternative is replaced.
    value_type &value() {
      if (!has_value()) {
        throw std::logic_error("result has no value");
      }
      return std::get<0>(storage_);
    }

    /// Borrow the stored value read-only; throws std::logic_error on failure.
    /// The reference expires when this result is destroyed or its alternative is replaced.
    const value_type &value() const {
      if (!has_value()) {
        throw std::logic_error("result has no value");
      }
      return std::get<0>(storage_);
    }

    /// Borrow failure detail; throws std::logic_error when this result contains a value.
    /// A throwing payload assignment that discarded both alternatives instead returns a static
    /// invalid_state error with unknown delivery and no native status or transport code.
    /// Stored detail expires when this result changes or dies; the fallback has static lifetime.
    [[nodiscard]] const operation_error &get_error() const {
      if (has_value()) {
        throw std::logic_error("result has no error");
      }
      if (storage_.valueless_by_exception()) {
        static const operation_error fallback{error_code::invalid_state, delivery_outcome::unknown};
        return fallback;
      }
      return std::get<1>(storage_);
    }
  };

  /// Success-or-error result for operations with no return payload.
  template <> class result<void> {
    std::optional<operation_error> error_;

    explicit result(std::optional<operation_error> error) : error_(std::move(error)) {}

  public:

    /// Construct success without a payload or allocation.
    static result success() { return result({}); }

    /// Copy the supplied failure detail into the result.
    static result failure(const operation_error &error) { return result(error); }

    /// Return true when no failure detail is stored.
    [[nodiscard]] bool has_value() const noexcept { return !error_; }

    /// Test success in a condition.
    explicit operator bool() const noexcept { return has_value(); }

    /// Borrow the stored error until this result changes or dies; throws on success.
    /// @throws std::logic_error This result does not contain an error.
    [[nodiscard]] const operation_error &get_error() const {
      if (!error_) {
        throw std::logic_error("result has no error");
      }
      return *error_;
    }
  };
} // namespace desfire

#endif // desfire_desfire_common_result_hpp
