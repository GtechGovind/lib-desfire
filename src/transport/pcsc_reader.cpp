/// @file
/// @brief PC/SC lifetime management and a single-send deadline adapter for WinSCard.

#include "pcsc_reader.hpp"
#include "apdu_codec.hpp"
#include "deadline_exchange.hpp"
#include <array>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <windows.h>
#include <winscard.h>

namespace desfire_console {
  namespace {

    /// Format the actual Windows error without logging APDUs, credentials or card data.
    pcsc_exception pcsc_error(
      const char *operation,
      LONG code
    ) {
      std::ostringstream message;
      message << operation << " failed: PC/SC 0x" << std::hex << std::uppercase
              << static_cast<std::uint32_t>(code);
      return pcsc_exception(message.str(), static_cast<int>(code));
    }

    /// Release the resource-manager context even when a later constructor step throws.
    struct context_handle {
      /// Resource-manager scope shared only by this context's reader operations.
      SCARDCONTEXT value{0};

      /// Open the current user's resource-manager scope; no card command is sent.
      context_handle() {
        const auto code = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &value);
        if (code != SCARD_S_SUCCESS) {
          throw pcsc_error("SCardEstablishContext", code);
        }
      }

      /// Context release cannot throw during unwinding.
      ~context_handle() { SCardReleaseContext(value); }

      /// Resource-manager ownership is never duplicated.
      context_handle(const context_handle &) = delete;
      /// Replacing a live scope by assignment is forbidden.
      context_handle &operator=(const context_handle &) = delete;
    };

    /// Convert a Windows reader name to UTF-8 without using the process code page.
    std::string to_utf8(const std::wstring &value) {
      const auto length = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1, nullptr, 0, nullptr, nullptr
      );
      if (length <= 0) {
        throw std::runtime_error("Reader name is not valid UTF-16");
      }
      std::string result(static_cast<std::size_t>(length), '\0');
      if (!WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            value.c_str(),
            -1,
            result.data(),
            length,
            nullptr,
            nullptr
          )) {
        throw std::runtime_error("Reader name conversion failed");
      }
      result.pop_back();
      return result;
    }

    /// Convert user input to Windows UTF-16 and reject malformed UTF-8.
    std::wstring to_wide(const std::string &value) {
      const auto length =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, nullptr, 0);
      if (length <= 0) {
        throw std::invalid_argument("Reader name is not valid UTF-8");
      }
      std::wstring result(static_cast<std::size_t>(length), L'\0');
      if (!MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, result.data(), length
          )) {
        throw std::runtime_error("Reader name conversion failed");
      }
      result.pop_back();
      return result;
    }

  } // namespace

  /// Context outlives the card handle; a detached deadline worker owns this whole object.
  struct pcsc_reader::session_state {
    /// Declared first so its lifetime extends beyond the card handle's cleanup.
    context_handle context;
    /// Exclusive physical connection, zero until SCardConnect succeeds.
    SCARDHANDLE handle{0};
    /// Negotiated T=0/T=1 protocol copied into each transmit control header.
    DWORD protocol{0};
    /// Activation metadata captured before the first APDU.
    desfire::bytes atr;
    /// Admission and quarantine state shared by callbacks for this physical connection.
    std::shared_ptr<deadline_exchange_state> exchange_state{
      std::make_shared<deadline_exchange_state>()
    };

    /// Reset once the last callback/worker releases the physical session.
    ~session_state() {
      if (handle != 0) {
        SCardDisconnect(handle, SCARD_RESET_CARD);
      }
    }
  };

  /// Query presence without selecting an application or authenticating a card.
  std::vector<reader_info> list_readers() {
    context_handle context;
    DWORD length = 0;
    auto code = SCardListReadersW(context.value, nullptr, nullptr, &length);
    if (code == SCARD_E_NO_READERS_AVAILABLE) {
      return {};
    }
    if (code != SCARD_S_SUCCESS) {
      throw pcsc_error("SCardListReaders", code);
    }
    std::vector<wchar_t> names(length);
    code = SCardListReadersW(context.value, nullptr, names.data(), &length);
    if (code != SCARD_S_SUCCESS) {
      throw pcsc_error("SCardListReaders", code);
    }
    std::vector<reader_info> result;
    for (const auto *name = names.data(); *name; name += std::wcslen(name) + 1) {
      SCARD_READERSTATEW state{};
      state.szReader = name;
      state.dwCurrentState = SCARD_STATE_UNAWARE;
      code = SCardGetStatusChangeW(context.value, 0, &state, 1);
      if (code != SCARD_S_SUCCESS) {
        throw pcsc_error("SCardGetStatusChange", code);
      }
      reader_info info;
      info.name = to_utf8(name);
      info.card_present = (state.dwEventState & SCARD_STATE_PRESENT) != 0;
      info.atr.assign(state.rgbAtr, state.rgbAtr + state.cbAtr);
      result.push_back(std::move(info));
    }
    return result;
  }

  /// Require an exact reader name supplied by the caller.
  std::string choose_reader(
    const std::vector<reader_info> &readers,
    const std::string &requested
  ) {
    std::vector<std::string> matches;
    for (const auto &reader : readers) {
      if (!requested.empty() && reader.name == requested) {
        matches.push_back(reader.name);
      }
    }
    if (matches.size() != 1) {
      throw std::invalid_argument("Specify an exact reader name returned by list_readers");
    }
    return matches.front();
  }

  /// Reserve one physical card exclusively and capture its activation metadata.
  pcsc_reader::pcsc_reader(
    const std::string &name,
    std::uint32_t wait_ms
  )
      : state_(std::make_shared<session_state>()) {
    const auto wide_name = to_wide(name);
    SCARD_READERSTATEW presence{};
    presence.szReader = wide_name.c_str();
    presence.dwCurrentState = SCARD_STATE_UNAWARE;
    auto code = SCardGetStatusChangeW(state_->context.value, 0, &presence, 1);
    if (code != SCARD_S_SUCCESS) {
      throw pcsc_error("SCardGetStatusChange", code);
    }
    if ((presence.dwEventState & SCARD_STATE_PRESENT) == 0) {
      presence.dwCurrentState = presence.dwEventState;
      code = SCardGetStatusChangeW(state_->context.value, wait_ms, &presence, 1);
      if (code == SCARD_E_TIMEOUT) {
        throw pcsc_error("Wait for card", code);
      }
      if (code == SCARD_S_SUCCESS && (presence.dwEventState & SCARD_STATE_PRESENT) == 0) {
        throw pcsc_error("No card present", SCARD_E_NO_SMARTCARD);
      }
      if (code != SCARD_S_SUCCESS) {
        throw pcsc_error("SCardGetStatusChange", code);
      }
    }
    code = SCardConnectW(
      state_->context.value,
      wide_name.c_str(),
      SCARD_SHARE_EXCLUSIVE,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
      &state_->handle,
      &state_->protocol
    );
    if (code != SCARD_S_SUCCESS) {
      throw pcsc_error("SCardConnect", code);
    }
    // A previous client may have left the powered card selected/authenticated. An
    // explicitly requested connection establishes fresh physical state before the
    // library can assume its initial PICC scope. No application APDU is replayed.
    code = SCardReconnect(
      state_->handle,
      SCARD_SHARE_EXCLUSIVE,
      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
      SCARD_RESET_CARD,
      &state_->protocol
    );
    if (code != SCARD_S_SUCCESS) {
      throw pcsc_error("SCardReconnect", code);
    }
    if (state_->protocol != SCARD_PROTOCOL_T0 && state_->protocol != SCARD_PROTOCOL_T1) {
      throw std::runtime_error("Reader did not negotiate T=0 or T=1");
    }
    std::array<std::uint8_t, sizeof(presence.rgbAtr)> activation{};
    DWORD activation_length = static_cast<DWORD>(activation.size());
    code =
      SCardGetAttrib(state_->handle, SCARD_ATTR_ATR_STRING, activation.data(), &activation_length);
    if (code != SCARD_S_SUCCESS) {
      throw pcsc_error("SCardGetAttrib(ATR)", code);
    }
    if (activation_length > activation.size()) {
      throw std::runtime_error("Reader returned an oversized ATR");
    }
    state_->atr.assign(activation.begin(), activation.begin() + activation_length);
  }

  /// Ownership is shared with callbacks so destruction never invalidates an active send.
  pcsc_reader::~pcsc_reader() = default;

  /// Read the stored ATR without another reader operation.
  const desfire::bytes &pcsc_reader::atr() const noexcept {
    return state_->atr;
  }

  bool pcsc_reader::requires_reconnect() const noexcept {
    std::lock_guard<std::mutex> lock(state_->exchange_state->mutex);
    return state_->exchange_state->quarantined;
  }

  /// WinSCard has no per-transmit deadline argument. Keep the worker's buffers/handle
  /// alive independently and quarantine after timeout rather than reusing an uncertain session.
  desfire::exchange_callback pcsc_reader::exchange() const {
    return exchange_impl(true);
  }

  /// Share admission with native commands while preserving standard SW1/SW2 response bytes.
  desfire::apdu_exchange_callback pcsc_reader::raw_exchange() const {
    return exchange_impl(false);
  }

  /// Decode native responses before the worker releases admission, closing the quarantine race.
  desfire::exchange_callback pcsc_reader::exchange_impl(bool native) const {
    return [state = state_,
            native](const std::uint8_t *data, std::size_t size, desfire::deadline deadline) {
      using exchange_result = desfire::result<desfire::bytes>;
      if (!native && (!data || size < 4 || size > 261)) {
        return exchange_result::failure({desfire::error_code::invalid_argument});
      }
      auto prepared = native ? wrap_command(data, size)
                             : exchange_result::success(desfire::bytes(data, data + size));
      if (!prepared) {
        return prepared;
      }
      auto command = std::move(prepared.value());
      // The sender owns the complete APDU and physical session even after an admitted timeout.
      return run_with_deadline(
        state->exchange_state, deadline, [state, native, apdu = std::move(command)]() {
          std::array<std::uint8_t, 258> buffer{};
          DWORD length = static_cast<DWORD>(buffer.size());
          SCARD_IO_REQUEST request{state->protocol, sizeof(SCARD_IO_REQUEST)};
          const auto code = SCardTransmit(
            state->handle,
            &request,
            apdu.data(),
            static_cast<DWORD>(apdu.size()),
            nullptr,
            buffer.data(),
            &length
          );
          if (code != SCARD_S_SUCCESS) {
            return exchange_result::failure(
              {desfire::error_code::transport_error,
               desfire::delivery_outcome::unknown,
               {},
               static_cast<int>(code)}
            );
          } else if (length < 2 || length > buffer.size()) {
            return exchange_result::failure(
              {desfire::error_code::malformed_response, desfire::delivery_outcome::unknown}
            );
          } else {
            desfire::bytes response(buffer.begin(), buffer.begin() + length);
            return native ? unwrap_response(response)
                          : exchange_result::success(std::move(response));
          }
        }
      );
    };
  }

} // namespace desfire_console
