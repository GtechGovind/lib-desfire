#include "../http/server.hpp"
#include <dashboard_resources.hpp>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <shellapi.h>
#include <windows.h>
#else
#include <csignal>
#endif

#ifndef DESFIRE_APP_VERSION
#define DESFIRE_APP_VERSION "0.2.0"
#endif

namespace {
#ifdef _WIN32
  volatile LONG shutdown_requested = 0;

  BOOL WINAPI console_control(DWORD event) {
    if (
      event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT ||
      event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT
    ) {
      InterlockedExchange(&shutdown_requested, 1);
      return TRUE;
    }
    return FALSE;
  }

  bool interrupted() {
    return InterlockedCompareExchange(&shutdown_requested, 0, 0) != 0;
  }
#else
  volatile std::sig_atomic_t shutdown_requested = 0;

  void console_control(int) {
    shutdown_requested = 1;
  }

  bool interrupted() {
    return shutdown_requested != 0;
  }
#endif

  class console_events final {

  public:

    console_events() {
#ifdef _WIN32
      if (!SetConsoleCtrlHandler(console_control, TRUE)) {
        throw std::runtime_error("Console shutdown handling could not be initialized.");
      }
#else
      previous_interrupt_ = std::signal(SIGINT, console_control);
      previous_terminate_ = std::signal(SIGTERM, console_control);
#endif
    }

    ~console_events() {
#ifdef _WIN32
      SetConsoleCtrlHandler(console_control, FALSE);
#else
      std::signal(SIGINT, previous_interrupt_);
      std::signal(SIGTERM, previous_terminate_);
#endif
    }

  private:

#ifndef _WIN32
    using signal_handler = void (*)(int);
    signal_handler previous_interrupt_ = SIG_DFL;
    signal_handler previous_terminate_ = SIG_DFL;
#endif
  };

  class shutdown_monitor final {

  public:

    explicit shutdown_monitor(desfire_console::http_server &server)
        : thread_([this,
                   &server] {
            while (!finished_.load()) {
              // The console callback only records an event. Socket operations and
              // thread joins happen in normal C++ execution, outside the callback.
              if (interrupted() && server.running()) {
                server.stop();
                return;
              }
              std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
          }) {}

    ~shutdown_monitor() {
      finished_.store(true);
      thread_.join();
    }

  private:

    std::atomic<bool> finished_{false};
    std::thread thread_;
  };

  std::vector<std::filesystem::path> command_line(
    int argc,
    char **argv
  ) {
    std::vector<std::filesystem::path> result;
#ifdef _WIN32
    (void)argc;
    (void)argv;
    int count = 0;
    auto **arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (arguments == nullptr) {
      throw std::runtime_error("Command-line arguments could not be read.");
    }
    try {
      for (int i = 0; i < count; ++i) {
        result.emplace_back(arguments[i]);
      }
    } catch (...) {
      LocalFree(arguments);
      throw;
    }
    LocalFree(arguments);
#else
    for (int i = 0; i < argc; ++i) {
      result.emplace_back(argv[i]);
    }
#endif
    return result;
  }

  std::filesystem::path executable_directory(const std::filesystem::path &argument_zero) {
#ifdef _WIN32
    (void)argument_zero;
    std::vector<wchar_t> buffer(256);
    while (buffer.size() <= 32768) {
      const auto count =
        GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
      if (count == 0) {
        break;
      }
      if (count < buffer.size()) {
        return std::filesystem::path(std::wstring(buffer.data(), count)).parent_path();
      }
      buffer.resize(buffer.size() * 2);
    }
    throw std::runtime_error("The executable directory could not be located.");
#else
    std::error_code error;
    const auto executable = std::filesystem::read_symlink("/proc/self/exe", error);
    return (error ? std::filesystem::absolute(argument_zero) : executable).parent_path();
#endif
  }

  std::uint16_t port_number(std::string_view argument) {
    unsigned int value = 0;
    const auto conversion =
      std::from_chars(argument.data(), argument.data() + argument.size(), value);
    if (
      argument.empty() || conversion.ec != std::errc{} ||
      conversion.ptr != argument.data() + argument.size() || value == 0 || value > 65535
    ) {
      throw std::invalid_argument("--port must be between 1 and 65535.");
    }
    return static_cast<std::uint16_t>(value);
  }

  void configure_crypto_modules(const std::filesystem::path &executable) {
#ifdef _WIN32
    SetLastError(ERROR_SUCCESS);
    const auto existing = GetEnvironmentVariableW(L"OPENSSL_MODULES", nullptr, 0);
    if (existing != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
      return;
    }
    const auto modules = executable / "ossl-modules";
    std::error_code error;
    if (
      std::filesystem::is_directory(modules, error) &&
      !SetEnvironmentVariableW(L"OPENSSL_MODULES", modules.c_str())
    ) {
      throw std::runtime_error("Cryptographic modules could not be configured.");
    }
#else
    (void)executable;
#endif
  }
}

int main(
  int argc,
  char **argv
) {
  try {
    const auto arguments = command_line(argc, argv);
    std::uint16_t port = 8765;
    std::filesystem::path assets;
    for (std::size_t i = 1; i < arguments.size(); ++i) {
      const auto option = arguments[i].u8string();
      if (option == "--help" || option == "-h") {
        std::cout
          << "DESFire local card console\n"
             "Usage: desfire_dashboard [--port PORT] [--assets DIRECTORY]\n"
             "  --port PORT          Listen on 127.0.0.1 (default: 8765).\n"
             "  --assets DIRECTORY   Read compiled frontend assets (default: executable/web).\n"
             "  --version            Print the application version.\n";
        return 0;
      }
      if (option == "--version") {
        std::cout << "desfire_dashboard " << DESFIRE_APP_VERSION << '\n';
        return 0;
      }
      if ((option == "--port" || option == "--assets") && i + 1 < arguments.size()) {
        ++i;
        if (option == "--port") {
          port = port_number(arguments[i].u8string());
        } else {
          assets = arguments[i];
        }
      } else {
        throw std::invalid_argument("Invalid arguments. Use --help for usage.");
      }
    }
    const auto executable = executable_directory(arguments.at(0));
    configure_crypto_modules(executable);
    if (assets.empty()) {
      assets = executable / "web";
    }
    const console_events events;
    const auto resource = desfire_console::command_catalog_resource();
    auto catalog = nlohmann::json::parse(resource.begin(), resource.end());
    desfire_console::http_server server(port, assets, std::move(catalog));
    const shutdown_monitor monitor(server);
    std::cout << "Card console: " << server.origin() << "/\n" << std::flush;
    if (!server.run()) {
      std::cerr << "The loopback HTTP server stopped unexpectedly.\n";
      return 1;
    }
    return 0;
  } catch (const std::invalid_argument &error) {
    std::cerr << error.what() << '\n';
  } catch (...) {
    // Startup errors are intentionally compact and never print arguments, file
    // contents, filesystem paths, command payloads or cryptographic material.
    std::cerr << "The card console could not start. Check the port and compiled assets.\n";
  }
  return 1;
}
