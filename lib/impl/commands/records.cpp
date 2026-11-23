/// @file
/// Record-file policies and byte-adapter entry points.
/// Read positions/counts use records while write offsets and data use bytes. The
/// clear record width validates response alignment and bounds count multiplication.

#include "../protocol/codec.hpp"
#include "builders.hpp"

namespace desfire::detail {

  /// Reuse native write framing and protection, changing only the WriteRecord opcode.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing payload protection.
  /// @param offset Byte offset within a record, fitting the native 24-bit range with data size.
  /// @param data Borrowed bytes copied into the request's erasing payload.
  /// @return Status-only, upload-chainable record policy or the shared write-validation error.
  command_result build_write_record(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    byte_view data
  ) {
    auto request = build_write_data(file, mode, offset, data);
    if (request) {
      request.value().opcode = 0x3b;
    }
    return request;
  }

  /// Build ReadRecords with overflow-safe clear-size and record-alignment constraints.
  /// @param file Native file number, 0..31.
  /// @param mode Response protection; MAC/encrypted mode requires authentication.
  /// @param first_record Starting record index, encoded as a 24-bit field.
  /// @param count Requested records, or zero for plain/MAC read-all only.
  /// @param record_size Nonzero clear record width in bytes, at most 24 bits.
  /// @return Read policy or invalid_argument; a nonzero count becomes an exact clear byte count
  /// computed in 64 bits before narrowing, and every verified response must contain whole records.
  command_result build_read_records(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t first_record,
    std::uint32_t count,
    std::uint32_t record_size
  ) {
    // Match native helper 0x1676C: encrypted records require a known clear byte count.
    if (
      file > 31 || !valid_mode(mode) || first_record > 0xffffff || count > 0xffffff ||
      record_size == 0 || record_size > 0xffffff ||
      static_cast<std::uint64_t>(first_record) + count > 0xffffff ||
      (mode == communication_mode::encrypted && count == 0)
    ) {
      return invalid_command();
    }
    const auto total = static_cast<std::uint64_t>(count) * record_size;
    if (total > 0xffffff) {
      return invalid_command();
    }
    auto request = management_command(
      0xbb,
      {file},
      count ? std::optional<std::size_t>(static_cast<std::size_t>(total)) : std::nullopt
    );
    append_u24_le(request.header, first_record);
    append_u24_le(request.header, count);
    request.response_mode = mode;
    request.legacy_mac_response = mode == communication_mode::mac;
    request.record_size = record_size;
    request.requires_authentication = mode != communication_mode::plain;
    return command_result::success(std::move(request));
  }

  /// Build an explicit clear of one selected native record file.
  /// @param file Native file number, 0..31.
  /// @return Status-only policy or invalid_argument; no transaction commit is added implicitly.
  command_result build_clear_record_file(std::uint8_t file) {
    if (file > 31) {
      return invalid_command();
    }
    return command_result::success(management_command(0xeb, {file}));
  }
} // namespace desfire::detail

namespace desfire {

  /// Write a borrowed byte sequence into a record under one serialized operation.
  /// @param file Native file number, 0..31.
  /// @param mode Outgoing data protection.
  /// @param offset Byte offset within the record.
  /// @param data Borrowed bytes, copied before transport callbacks run.
  /// @return Verified status-only result; uncertain delivery is never replayed automatically.
  result<void> card::write_record_bytes(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t offset,
    detail::byte_view data
  ) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_write_record(file, mode, offset, data);
    });
  }

  /// Read verified whole records after checking requested clear bytes against the card limit.
  /// @param file Native file number, 0..31.
  /// @param mode Response protection policy.
  /// @param first_record Starting index in records.
  /// @param count Requested record count; zero permits only plain/MAC read-all.
  /// @param record_size Expected width of one clear record in bytes.
  /// @return Owned clear bytes aligned to record_size, or a validation/transport/protection error;
  /// 64-bit multiplication prevents wrapped preflight sizes.
  result<bytes> card::read_records(
    std::uint8_t file,
    communication_mode mode,
    std::uint32_t first_record,
    std::uint32_t count,
    std::uint32_t record_size
  ) {
    return detail::run_command<bytes>(
      mutable_state(),
      [&] {
        if (
          static_cast<std::uint64_t>(count) * record_size >
          mutable_state().options.max_response_size
        ) {
          return detail::invalid_command();
        }
        return detail::build_read_records(file, mode, first_record, count, record_size);
      },
      [](detail::byte_view data) {
        return result<bytes>::success(bytes(data.begin(), data.end()));
      }
    );
  }

  /// Stage clearing a record file through one explicit native command.
  /// @param file Native file number, 0..31.
  /// @return Verified status-only result; the caller chooses a later commit or abort.
  result<void> card::clear_record_file(std::uint8_t file) {
    return detail::run_void_command(mutable_state(), [&] {
      return detail::build_clear_record_file(file);
    });
  }
} // namespace desfire
