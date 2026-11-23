/// @file
/// Explicit native transaction completion policies.
/// Neither completion command is retried automatically: transport uncertainty may
/// mean the card already applied the requested mutation.

#include "builders.hpp"

namespace desfire::detail {

  /// Build one CommitTransaction with no payload and exact status-only completion.
  /// @return Management policy; a modern session advances/verifies its retained MAC state.
  command_result build_commit_transaction() {
    return command_result::success(management_command(0xc7));
  }

  /// Build one AbortTransaction with no payload and exact status-only completion.
  /// @return Management policy; a modern session advances/verifies its retained MAC state.
  command_result build_abort_transaction() {
    return command_result::success(management_command(0xa7));
  }
} // namespace desfire::detail

namespace desfire {

  /// Commit staged card changes through one serialized native command.
  /// @return Verified status-only success or the original operation error, including unknown
  /// delivery; no implicit retry can accidentally commit a later transaction.
  result<void> card::commit_transaction() {
    return detail::run_void_command(mutable_state(), detail::build_commit_transaction);
  }

  /// Abort staged card changes through one serialized native command.
  /// @return Verified status-only success or the original operation error; no automatic retry is
  /// sent.
  result<void> card::abort_transaction() {
    return detail::run_void_command(mutable_state(), detail::build_abort_transaction);
  }
} // namespace desfire
