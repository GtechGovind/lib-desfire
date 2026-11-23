/// @file
/// @brief Synchronous native and standard DESFire commands with bounded range overloads.

#ifndef desfire_card_hpp
#define desfire_card_hpp

#include "buffer/buffer_helpers.hpp"
#include "iso7816/binary.hpp"
#include "iso7816/records.hpp"
#include "iso7816/selection.hpp"
#include "iso7816/status.hpp"
#include "model/application.hpp"
#include "model/file.hpp"
#include "model/options.hpp"
#include "model/version.hpp"
#include "transport/apdu_callback.hpp"
#include "transport/callback.hpp"
#include <memory>
#include <string_view>

namespace desfire {
  namespace detail {
    /// Private compiled session state; backend types do not enter the public interface.
    struct card_state;
  } // namespace detail

  /// One host session bound to one already activated physical card.
  ///
  /// The instance owns its synchronous exchange callbacks. Captured reader resources must outlive
  /// it. Concurrent and reentrant command execution returns error_code::busy; the caller must keep
  /// this object alive throughout every call. No command or monetary mutation is automatically
  /// retried. An unknown delivery outcome requires physical reactivation and a fresh, aligned host
  /// session. init() only resets host state and cannot establish what the card previously executed.
  /// Native preparation that discards host credentials also requires reactivation, even if
  /// delivery is not_sent and the card still holds the preceding authentication.
  ///
  /// Every command returns result. Failures preserve the available protocol status and delivery
  /// certainty. Argument validation, known-capacity preflight and input-collection failures occur
  /// before reader I/O. Unknown-length reads can report insufficient output capacity after verified
  /// execution, with delivery_outcome::succeeded. Reads expose a payload only after the checks
  /// required by the active session and mode succeed.
  /// Native file numbers are 0..31 and key numbers are 0..13. Communication modes must match
  /// the card's file policy.
  ///
  /// Input templates accept char, signed/unsigned char and std::byte ranges: vector, array, C
  /// array, string and string_view are supported. Their size is exact, including a C array's
  /// trailing NUL. Contiguous inputs are borrowed until return; other inputs are collected once and
  /// the temporary is erased. Iterator pairs may be single-pass input iterators. Original caller
  /// storage is never erased. Keep each input alive and unchanged until its synchronous call
  /// returns.
  ///
  /// Authentication key validation errors preserve preceding credentials. A failed handshake
  /// that reached the card clears the host credentials. A verified proof installs the new
  /// session. A later host deadline error with delivery_outcome::succeeded retains it.
  ///
  /// Output templates require existing bounded writable byte ranges with forward iterators
  /// yielding assignable nonconst lvalue references.
  /// Capacity is the range's current element count. A capacity error leaves the destination
  /// untouched. Custom output range and iterator operations must not throw. An output iterator
  /// exception during copying can leave a partial host copy after successful card execution.
  class card {
    /// Owns all authentication, transport and admission state for this instance.
    std::unique_ptr<detail::card_state> state_;

    /// Return the immutable bound used for generic input normalization.
    [[nodiscard]] std::size_t max_input_size() const noexcept;

    /// Borrow mutable protocol state only through a nonconst card facade.
    /// Even reads may advance authentication IVs, continuation and transport admission state.
    //noinspection CppMemberFunctionMayBeConst
    [[nodiscard]] detail::card_state &mutable_state() noexcept;

    /// Enter authentication after generic key storage has been normalized.
    result<void> authenticate_bytes(
      authentication_type family,
      std::uint8_t number,
      key_type type,
      detail::byte_view key
    );

    /// Encode a PICC key change while the normalized replacement key remains borrowed.
    result<void> change_picc_master_key_bytes(
      key_type type,
      detail::byte_view key,
      std::uint8_t version
    );

    /// Encode an application key change with both normalized key ranges alive.
    result<void> change_app_key_bytes(
      std::uint8_t number,
      detail::byte_view old_key,
      detail::byte_view new_key,
      std::uint8_t version
    );

    /// Replace explicitly typed keys while both borrowed views are alive under operation admission.
    result<void> change_app_key_bytes(
      std::uint8_t number,
      key_type old_type,
      detail::byte_view old_key,
      key_type new_type,
      detail::byte_view new_key,
      std::uint8_t version
    );

    /// Validate and encode creation metadata and an optional raw DF name.
    result<void> create_application_bytes(
      const application_config &config,
      detail::byte_view name
    );

    /// Apply the retained native option policy to normalized configuration bytes.
    result<void> set_configuration_bytes(
      std::uint8_t option,
      detail::byte_view data
    );

    /// Encode bounded native data writes without container-specific protocol instantiations.
    result<void> write_data_bytes(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      detail::byte_view data
    );

    /// Encode bounded native record writes while the caller's normalized data remains alive.
    result<void> write_record_bytes(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      detail::byte_view data
    );

    /// Borrow the exact DF name through the admitted standard selection operation.
    result<iso7816_response> iso7816_select_by_df_name_bytes(
      detail::byte_view name,
      iso7816_select_response response
    );

    /// Validate a binary target, then submit the borrowed data in one UPDATE BINARY operation.
    result<void> iso7816_update_binary_bytes(
      const iso7816_binary_address &address,
      detail::byte_view data
    );

    /// Encode selected-EF or short-ID addressing for one APPEND RECORD operation.
    result<void> iso7816_append_record_bytes(
      const iso7816_record_address &address,
      detail::byte_view data
    );

    /// Validate borrowed static key material and complete the standard handshake under admission.
    result<void> iso7816_authenticate_bytes(
      std::uint8_t number,
      key_type type,
      detail::byte_view key
    );

  public:

    /// Bind a callback and copy immutable options without performing reader I/O.
    /// Options and callback validity are checked when an operation is attempted.
    /// @param exchange Single-send callback for the already activated card.
    /// @param options Deadline, frame, response and continuation bounds for every operation.
    /// @throws std::bad_alloc Host session allocation failed.
    explicit card(
      exchange_callback exchange,
      card_options options = {}
    );

    /// Own separate native and raw APDU adapters for the same already activated card.
    /// Construction sends no frame. An admitted exchange validates the limits for its protocol.
    /// @param native_exchange Single-send native adapter returning status followed by data.
    /// @param apdu_exchange Single-send standard adapter returning data followed by SW1/SW2.
    /// An empty adapter disables standard APDU operations.
    /// @param options Limits copied into the session.
    /// @throws std::bad_alloc Host session allocation failed.
    card(
      exchange_callback native_exchange,
      apdu_exchange_callback apdu_exchange,
      card_options options
    );

    /// Select the master file using ISO identifier 0x3F00.
    /// Successful selection clears authentication and establishes native PICC scope.
    /// @param response Request iso7816_select_response::none for the status-only response.
    /// @return The exact ISO status on success, or a delivery-aware error.
    result<iso7816_response> iso7816_select_master_file(iso7816_select_response response);

    /// Select a child DF or EF using a big-endian ISO file identifier.
    /// DF selection clears authentication and leaves the native AID unmapped. EF selection
    /// preserves the current DF and authentication. FCI is available for DF selection only.
    /// @param identifier Numeric file identifier. This API excludes 0, 0x3F00, 0x3FFF and 0xFFFF.
    /// @param scope Whether the identifier addresses an application DF or an EF.
    /// @param response Status only, or raw FCI for an application DF.
    /// @return Owned response bytes and exact ISO status, or a delivery-aware error. A malformed
    /// payload after a completed selection reports succeeded delivery.
    result<iso7816_response> iso7816_select_file(
      std::uint16_t identifier,
      iso7816_file_scope scope,
      iso7816_select_response response
    );

    /// Select a DF by exact name and clear authentication on successful selection.
    /// The registered DESFire PICC name establishes PICC scope and supports status only. Other
    /// names establish application scope with an unmapped native AID.
    /// @param name A range of 1..16 raw bytes, including any trailing NUL in the range.
    /// @param response Status only, or raw FCI for an application DF.
    /// @return Owned data and exact status, or a delivery-aware error as for file selection.
    template <class range>
    result<iso7816_response> iso7816_select_by_df_name(
      const range &name,
      iso7816_select_response response
    );

    /// Select using 1..16 exact name bytes from the single-pass range [first, last).
    /// The name copy is erased after use. Selection and response follow the range overload.
    template <class iterator>
    result<iso7816_response> iso7816_select_by_df_name(
      iterator first,
      iterator last,
      iso7816_select_response response
    );

    /// Read from a selected binary EF or from a short file ID in the current DF.
    /// Unauthenticated reads accept 1..256 clear bytes, preserve EOF status 0x6282 and may follow
    /// bounded GET RESPONSE continuations. EV1-authenticated reads accept 1..248 clear bytes and
    /// require a successful status and verified response CMAC. Native legacy authentication is
    /// unsupported for standard reads. Success with a short ID selects that EF.
    /// @param request Address and maximum clear byte count.
    /// @return Owned verified data with exact ISO status, or a delivery-aware error.
    result<iso7816_response> iso7816_read_binary(const iso7816_binary_read &request);

    /// Copy verified binary data into an existing writable byte range.
    /// Capacity is checked against the received clear length. An undersized destination remains
    /// intact and the error carries succeeded delivery and the exact ISO status.
    /// @param request Address and maximum clear byte count.
    /// @param output Caller-owned writable storage.
    /// @return Bytes written and exact ISO status, including supported EOF, or a delivery-aware
    /// error.
    template <class output_range>
    result<iso7816_read_result> iso7816_read_binary_into(
      const iso7816_binary_read &request,
      output_range &output
    );

    /// Copy verified binary data to the writable forward range [first, last).
    /// Capacity and status handling follow the writable range overload.
    template <class output_iterator>
    result<iso7816_read_result> iso7816_read_binary_into(
      const iso7816_binary_read &request,
      output_iterator first,
      output_iterator last
    );

    /// Send one plain UPDATE BINARY APDU with 1..255 bytes, subject to the configured APDU limit.
    /// A successful write can persist immediately, including on backup files. Success with a
    /// short ID selects that EF.
    /// @param address Selected-EF or short-ID target and starting offset.
    /// @param data Raw bytes to write.
    /// @return Status-only success or a delivery-aware error.
    template <class range>
    result<void> iso7816_update_binary(
      const iso7816_binary_address &address,
      const range &data
    );

    /// Update binary data from the single-pass range [first, last).
    /// Data bounds, selection and persistence follow the range overload.
    template <class iterator>
    result<void> iso7816_update_binary(
      const iso7816_binary_address &address,
      iterator first,
      iterator last
    );

    /// Read records in card order from a starting record numbered 1..254. A cyclic file starts
    /// at its newest record. Length, protection, EOF and short-ID selection follow
    /// iso7816_read_binary().
    /// @param request Record address, starting record, traversal mode and maximum clear length.
    /// @return Owned verified record bytes and exact ISO status, or a delivery-aware error.
    result<iso7816_response> iso7816_read_records(const iso7816_record_read &request);

    /// Copy verified record bytes into existing writable storage.
    /// Capacity, EOF and succeeded delivery on an undersized destination follow
    /// iso7816_read_binary_into().
    /// @param request Record address, starting record, traversal mode and maximum clear length.
    /// @param output Caller-owned writable storage.
    /// @return Bytes written and exact ISO status, or a delivery-aware error.
    template <class output_range>
    result<iso7816_read_result> iso7816_read_records_into(
      const iso7816_record_read &request,
      output_range &output
    );

    /// Copy verified records to the writable forward range [first, last).
    /// Capacity and status handling follow the writable range overload.
    template <class output_iterator>
    result<iso7816_read_result> iso7816_read_records_into(
      const iso7816_record_read &request,
      output_iterator first,
      output_iterator last
    );

    /// Append 1..255 bytes in a single plain APDU, subject to the configured APDU limit.
    /// The card controls width, linear or cyclic behavior, and persistence. Success with a short
    /// ID selects that EF.
    /// @param address Selected-EF or short-ID target.
    /// @param data Raw record bytes.
    /// @return Status-only success or a delivery-aware error.
    template <class range>
    result<void> iso7816_append_record(
      const iso7816_record_address &address,
      const range &data
    );

    /// Append a record from the single-pass range [first, last).
    /// Data bounds, selection and persistence follow the range overload.
    template <class iterator>
    result<void> iso7816_append_record(
      const iso7816_record_address &address,
      iterator first,
      iterator last
    );

    /// Request a standalone challenge. A delivered request clears preceding authentication.
    /// The complete authentication method requests its own fresh challenge.
    /// @param type Static key algorithm. DES and 2K3DES request 8 bytes. 3K3DES and AES request 16.
    /// @return Owned challenge bytes or a delivery-aware error.
    result<bytes> iso7816_get_challenge(key_type type);

    /// Perform GET CHALLENGE, EXTERNAL AUTHENTICATE and INTERNAL AUTHENTICATE under one deadline.
    /// The selected scope determines whether the key reference is for the PICC or an application.
    /// An unknown selection must be reestablished before authentication.
    /// @param number Key number 0 for PICC or 0..13 for an application.
    /// @param type Algorithm determining the exact static key width.
    /// @param key Raw static key. Keep its storage alive through the call.
    /// @return Success after verified proof installs the derived session, or a delivery-aware
    /// error.
    template <class range>
    result<void> iso7816_authenticate(
      std::uint8_t number,
      key_type type,
      const range &key
    );

    /// Authenticate using the exact static key bytes in the single-pass range [first, last).
    /// The normalized key is erased on return. Scope and proof follow the range overload.
    template <class iterator>
    result<void> iso7816_authenticate(
      std::uint8_t number,
      key_type type,
      iterator first,
      iterator last
    );

    /// Erase host authentication material and release the exchange callbacks without reader I/O.
    ~card();

    /// A physical card's live protocol state cannot be duplicated.
    card(const card &) = delete;

    /// Replacing another card's live session by copying is forbidden.
    card &operator=(const card &) = delete;

    /// Keep the state and its admission lock at one stable object identity.
    card(card &&) = delete;

    /// Replacing a live card session by moving is forbidden.
    card &operator=(card &&) = delete;

    /// Clear host authentication and uncertainty, preserving the last known application selection.
    /// Sends no command and cannot establish the physical card's state or abort pending changes.
    /// After external reset/reactivation, select_application() must explicitly resynchronize scope.
    /// Returns busy if another operation owns this instance.
    result<void> init();

    /// Return this implementation's version as a process-lifetime static string view.
    static std::string_view get_library_version() noexcept;

    /// Authenticate with native 0x0A using an 8-byte DES or 16-byte two-key TDES key.
    /// Equal TDES halves use single-DES session derivation.
    /// @param number Key in the selected PICC/application scope.
    /// @param type key_type::des or key_type::tdes_2k; other families are rejected.
    /// @param key Raw key bytes, borrowed or temporarily normalized according to the class
    /// contract.
    template <class range>
    result<void> authenticate(
      std::uint8_t number,
      key_type type,
      const range &key
    );

    /// Authenticate with native 0x0A from the raw key bytes in the single-pass range [first,last).
    /// number and type have the same meaning and key-width rules as the range overload.
    template <class iterator>
    result<void> authenticate(
      std::uint8_t number,
      key_type type,
      iterator first,
      iterator last
    );

    /// Authenticate with native 0x1A using DES, two-key TDES or three-key TDES.
    /// This protocol is distinct from ISO 7816 external authentication.
    /// @param number Key in the selected scope.
    /// @param type Cipher family determining an exact 8-, 16- or 24-byte raw key width.
    /// @param key Caller-owned raw key range; AES is rejected by this entry point.
    template <class range>
    result<void> authenticate_iso(
      std::uint8_t number,
      key_type type,
      const range &key
    );

    /// Authenticate with native 0x1A after collecting the raw key range [first,last) once.
    /// number and type select the scoped key and DES/TDES family as in the range overload.
    template <class iterator>
    result<void> authenticate_iso(
      std::uint8_t number,
      key_type type,
      iterator first,
      iterator last
    );

    /// Authenticate key number with native 0xAA using exactly sixteen raw AES-128 bytes.
    /// A verified card proof installs the new session; the caller retains ownership of key.
    template <class range>
    result<void> authenticate_aes(
      std::uint8_t number,
      const range &key
    );

    /// Authenticate scoped key number with sixteen AES bytes from the input range [first,last).
    /// The range is consumed once and its temporary copy is erased after authentication.
    template <class iterator>
    result<void> authenticate_aes(
      std::uint8_t number,
      iterator first,
      iterator last
    );

    /// Replace key-settings byte one using encrypted protection under the authenticated session.
    /// @param settings Exact policy byte; key-family/count byte two is unchanged by this command.
    result<void> change_key_settings(std::uint8_t settings);

    /// Return both raw key-settings bytes for the selected application or PICC.
    result<key_settings> get_key_settings();

    /// Return the version byte of key number in the currently selected scope.
    result<std::uint8_t> get_key_version(std::uint8_t number);

    /// Replace PICC key zero, optionally changing its cipher family; requires PICC selection.
    /// Successful replacement clears authentication, so authenticate again before protected use.
    /// @param type Replacement family, determining the exact 8-, 16- or 24-byte key width.
    /// @param key Raw replacement bytes retained by the caller.
    /// @param version AES version byte; DES/TDES versions remain encoded in the supplied key bits.
    template <class range>
    result<void> change_picc_master_key(
      key_type type,
      const range &key,
      std::uint8_t version
    );

    /// Replace PICC key zero with raw key bytes collected once from [first,last).
    /// type and version follow the range overload; temporary key bytes are erased before return.
    template <class iterator>
    result<void> change_picc_master_key(
      key_type type,
      iterator first,
      iterator last,
      std::uint8_t version
    );

    /// Replace a key in a known nonzero native AID, using the session's effective cipher family.
    /// Replacing the authenticated key clears authentication on success. Both ranges must have the
    /// active family's exact width, even when replacing the current key does not use the old bytes.
    /// @param number Application key number, 0..13.
    /// @param old_key Previous raw key, used for XOR when changing a different key.
    /// @param new_key Replacement raw key; neither original range is modified or erased.
    /// @param version AES version byte; DES/TDES version bits are carried in new_key.
    template <
      class old_range,
      class new_range>
    result<void> change_app_key(
      std::uint8_t number,
      const old_range &old_key,
      const new_range &new_key,
      std::uint8_t version
    );

    /// Replace a key in a known nonzero native AID from the two exact iterator ranges.
    /// Both input pairs are consumed once, normalized copies are erased, and version follows the
    /// range overload. Keep both original ranges valid until this call returns.
    template <
      class old_iterator,
      class new_iterator>
    result<void> change_app_key(
      std::uint8_t number,
      old_iterator old_first,
      old_iterator old_last,
      new_iterator new_first,
      new_iterator new_last,
      std::uint8_t version
    );

    /// Replace a key using explicitly typed material and the installed session's protection.
    /// DES and 2K3DES share one application family. DES inputs are duplicated on the wire.
    /// An explicit nonzero native AID must be selected. Other application families require both
    /// key types to match the authenticated family.
    /// @param number Application key number, 0..13.
    /// @param old_type Type declaring the exact width of old_key.
    /// @param old_key Previous raw key, used for the other-key XOR construction.
    /// @param new_type Type declaring the exact width of new_key.
    /// @param new_key Replacement raw key with DES/TDES version bits already set as desired.
    /// @param version Version byte appended only for AES.
    /// @return Verified status or a delivery-aware error. Invalid input fails before I/O, and
    /// replacing the authenticated key clears authentication on success. Contiguous ranges are
    /// borrowed for this synchronous operation. Other ranges are collected once and erased.
    template <
      class old_range,
      class new_range>
    result<void> change_app_key(
      std::uint8_t number,
      key_type old_type,
      const old_range &old_key,
      key_type new_type,
      const new_range &new_key,
      std::uint8_t version
    );

    /// Replace a key from explicit types and single-pass input iterator pairs.
    /// @param number Application key number, 0..13.
    /// @param old_type Type determining the required extent of [old_first, old_last).
    /// @param old_first Beginning of the previous key material.
    /// @param old_last Exclusive limit of the previous key material.
    /// @param new_type Type determining the required extent of [new_first, new_last).
    /// @param new_first Beginning of the replacement key material.
    /// @param new_last Exclusive limit of the replacement key material.
    /// @param version Version byte appended only for AES.
    /// @return The same result as the typed range overload. Both pairs are consumed at most
    /// once and any temporary material is erased on return, including validation failures.
    template <
      class old_iterator,
      class new_iterator>
    result<void> change_app_key(
      std::uint8_t number,
      key_type old_type,
      old_iterator old_first,
      old_iterator old_last,
      key_type new_type,
      new_iterator new_first,
      new_iterator new_last,
      std::uint8_t version
    );

    /// Create an application from explicit native settings and optional ISO ID, with no DF name.
    /// The administrative change is not undone by abort_transaction(). config is copied into wire
    /// fields during this call; its application ID must be nonzero and fit 24 bits.
    result<void> create_application(const application_config &config);

    /// Create config's application with at most sixteen raw DF-name bytes from name.
    /// A nonempty name requires ISO metadata; bytes are used as supplied, without text conversion.
    template <class range>
    result<void> create_application(
      const application_config &config,
      const range &name
    );

    /// Create config's application with a DF name collected once from [first,last).
    /// The sixteen-byte limit and ISO metadata requirements match the named-range overload.
    template <class iterator>
    result<void> create_application(
      const application_config &config,
      iterator first,
      iterator last
    );

    /// Delete nonzero 24-bit application id; abort_transaction() cannot restore the application.
    result<void> delete_application(std::uint32_t id);

    /// Return owned numeric 24-bit application IDs in card response order.
    /// All continuation frames share the operation's deadline and configured bounds.
    result<std::vector<std::uint32_t>> get_application_ids();

    /// Select 24-bit application id, or zero for PICC scope, clearing host authentication first.
    /// Reauthenticate after selection; a definite selection failure does not restore old
    /// credentials.
    result<void> select_application(std::uint32_t id);

    /// Return owned DF directory records while preserving each physical response-record boundary.
    /// No entry is exposed until the complete command response passes the applicable checks.
    result<std::vector<df_name_entry>> get_df_names();

    /// Format the card from authenticated PICC scope; success clears host authentication.
    /// This administrative deletion is not reversed by abort_transaction().
    result<void> format_picc();

    /// Return decoded hardware, software, UID and manufacturing fields from all 28 response bytes.
    result<version_info> get_version();

    /// Return the card's unsigned 24-bit free-memory count in bytes.
    result<std::uint32_t> free_memory();

    /// Apply the supported SetConfiguration option layouts under authentication.
    /// @param option 0 uses data's first byte masked by 0x03; 2 sends raw data with marker padding;
    /// 3 sends no option data. Option 1 and values above 3 are rejected.
    /// @param data Nonempty raw input for all accepted options; option 3 ignores its bytes.
    template <class range>
    result<void> set_configuration(
      std::uint8_t option,
      const range &data
    );

    /// Apply configuration option using raw input collected once from [first,last).
    /// The range must be nonempty even for option 3, which emits no payload.
    template <class iterator>
    result<void> set_configuration(
      std::uint8_t option,
      iterator first,
      iterator last
    );

    /// Return seven owned UID bytes in card order from an authenticated encrypted response.
    result<bytes> get_card_uid();

    /// Return owned native file-number entries in the selected application, without padding.
    result<std::vector<std::uint8_t>> get_fids();

    /// Return owned ISO file IDs decoded as numeric 16-bit values in response order.
    result<std::vector<std::uint16_t>> get_iso_fids();

    /// Return file's parsed policy and type-specific geometry; the variant matches its file type.
    /// GetFileSettings does not supply an ISO file ID, so none is fabricated in this result.
    result<file_settings> get_file_settings(std::uint8_t file);

    /// Apply file's new mode/access policy using settings.encrypted_command for request protection.
    /// The new file mode and protection of this ChangeFileSettings command are independent choices.
    result<void> change_file_settings(
      std::uint8_t file,
      const file_settings_change &settings
    );

    /// Create file as standard data storage; config supplies byte size, policy and optional ISO ID.
    /// Standard-file writes take effect without a transaction commit.
    result<void> create_std_data_file(
      std::uint8_t file,
      const data_file_config &config
    );

    /// Create file as transactional backup data storage with config's size and policy.
    /// Subsequent writes remain staged until an explicit commit or abort.
    result<void> create_backup_data_file(
      std::uint8_t file,
      const data_file_config &config
    );

    /// Create file as a signed value file, validating config's initial value against both bounds.
    /// Values and credit/debit amounts use caller-defined units; no currency conversion is applied.
    result<void> create_value_file(
      std::uint8_t file,
      const value_file_config &config
    );

    /// Create file as a linear record file with config's nonzero record width and capacity.
    result<void> create_linear_record_file(
      std::uint8_t file,
      const record_file_config &config
    );

    /// Create file as a cyclic record file with config's nonzero record width and capacity.
    result<void> create_cyclic_record_file(
      std::uint8_t file,
      const record_file_config &config
    );

    /// Delete file administratively; an abort cannot restore the removed file.
    result<void> delete_file(std::uint8_t file);

    /// Return owned verified data bytes from file using its actual communication mode.
    /// @param file Native file number, 0..31.
    /// @param mode Current on-card communication policy for this file.
    /// @param offset Unsigned 24-bit byte offset within the file.
    /// @param length Unsigned 24-bit byte count. Plain/MAC mode permits zero for all remaining
    /// bytes, bounded by response/deadline limits. Encrypted mode requires a nonzero exact count:
    /// CRC and zero padding cannot reliably identify an unknown clear length.
    /// Offset plus length must also fit the native 24-bit bound.
    result<bytes> read_data(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      std::uint32_t length
    );

    /// Write raw data to file at a 24-bit byte offset, using the actual file mode.
    /// Backup-file changes require explicit commit; standard-file changes take effect immediately.
    /// Input size and offset plus size must fit the native 24-bit address space and configured
    /// bound.
    template <class range>
    result<void> write_data(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      const range &data
    );

    /// Write file data from the single-pass byte range [first,last) at byte offset using mode.
    /// The size/offset and transaction rules match the range overload; collected bytes are erased.
    template <class iterator>
    result<void> write_data(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      iterator first,
      iterator last
    );

    /// Return file's verified signed 32-bit balance using the actual file mode, without unit
    /// changes.
    result<std::int32_t> get_value(
      std::uint8_t file,
      communication_mode mode
    );

    /// Stage a nonnegative signed-32-bit credit amount to file using its mode; commit is explicit.
    /// An unknown delivery outcome must be reconciled before another monetary mutation is
    /// attempted.
    result<void> credit(
      std::uint8_t file,
      communication_mode mode,
      std::int32_t amount
    );

    /// Stage a nonnegative signed-32-bit debit amount from file using its mode; commit is explicit.
    /// The core never retries a debit whose delivery or completion cannot be established.
    result<void> debit(
      std::uint8_t file,
      communication_mode mode,
      std::int32_t amount
    );

    /// Stage a nonnegative limited credit amount to file using its mode and card-side credit
    /// policy. Card limits still apply and successful staging requires an explicit commit.
    result<void> limited_credit(
      std::uint8_t file,
      communication_mode mode,
      std::int32_t amount
    );

    /// Write raw record data at a 24-bit byte offset, using file's actual communication mode.
    /// This is a byte offset within a record, distinct from read_records()' record index.
    /// Record changes remain staged until explicit commit or abort; input is bounded like
    /// write_data().
    template <class range>
    result<void> write_record(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      const range &data
    );

    /// Write record bytes collected once from [first,last), using file, mode and byte offset.
    /// The range overload's byte limits and transaction rules apply; temporary data is erased.
    template <class iterator>
    result<void> write_record(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      iterator first,
      iterator last
    );

    /// Return owned verified record bytes using file's actual mode and record geometry.
    /// @param file Native record-file number, 0..31.
    /// @param mode Current on-card communication policy for this file.
    /// @param first_record Unsigned 24-bit record index, distinct from a byte offset.
    /// @param count Unsigned 24-bit record count. Plain/MAC permits zero for all available
    /// records; encrypted mode requires a nonzero exact count to locate its CRC and padding.
    /// @param record_size Nonzero 24-bit record width in bytes, used to verify response boundaries.
    /// First record plus count must fit the native 24-bit bound.
    /// Requested total bytes must fit the native 24-bit bound and configured maximum response size.
    result<bytes> read_records(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t first_record,
      std::uint32_t count,
      std::uint32_t record_size
    );

    /// Stage removal of all records in file; confirmed commit finalizes it and abort cancels it.
    result<void> clear_record_file(std::uint8_t file);

    /// Finalize staged backup, value and record changes once.
    /// A missing or unverifiable reply is unknown and is not evidence of rollback.
    result<void> commit_transaction();

    /// Request cancellation of staged transactions once; does not undo administrative changes.
    /// Only a confirmed response establishes cancellation; an uncertain reply does not prove
    /// rollback.
    result<void> abort_transaction();

    /// Read file data at byte offset into existing output elements using mode and length as
    /// read_data(). A nonzero length is capacity-checked before I/O; length zero checks the actual
    /// verified size.
    /// @return Number of bytes written. A post-read capacity error reports succeeded delivery and
    /// leaves output untouched; unused destination elements retain their previous values.
    template <class range>
    result<std::size_t> read_data_into(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      std::uint32_t length,
      range &output
    );

    /// Read data into the bounded writable forward range [first,last), returning bytes written.
    /// file, mode, offset, length and capacity-failure behavior match the output-range overload.
    template <class iterator>
    result<std::size_t> read_data_into(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t offset,
      std::uint32_t length,
      iterator first,
      iterator last
    );

    /// Read file records into existing output elements with read_records()' mode/index/geometry
    /// rules. Nonzero count permits a complete capacity check before I/O; count zero checks
    /// verified size.
    /// @return Byte count written. Insufficient capacity never copies a prefix; after a successful
    /// card read, this host capacity error reports delivery_outcome::succeeded.
    template <class range>
    result<std::size_t> read_records_into(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t first_record,
      std::uint32_t count,
      std::uint32_t record_size,
      range &output
    );

    /// Read records into the bounded writable forward range [first,last), returning bytes written.
    /// file, mode, first_record, count, record_size and capacity behavior match the range overload.
    template <class iterator>
    result<std::size_t> read_records_into(
      std::uint8_t file,
      communication_mode mode,
      std::uint32_t first_record,
      std::uint32_t count,
      std::uint32_t record_size,
      iterator first,
      iterator last
    );

    /// Copy the authenticated seven-byte UID into existing output; return seven on success.
    /// Capacity below seven fails before reader I/O and leaves the destination unchanged.
    template <class range> result<std::size_t> get_card_uid_into(range &output);

    /// Copy the UID into bounded writable forward range [first,last); require seven elements.
    /// Capacity and delivery behavior match the output-range overload.
    template <class iterator>
    result<std::size_t> get_card_uid_into(
      iterator first,
      iterator last
    );
  };

}

#include "card_templates.hpp" // IWYU pragma: export

#endif // desfire_card_hpp
