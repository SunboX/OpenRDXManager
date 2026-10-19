// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <node_api.h>
#include "windows_log_files.h"
#include "windows_pipe_io.h"

#include <windows.h>
#include <shlobj.h>
#include <sddl.h>
#include <winsvc.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// Native trust policy is shared with the Rust service; successful leases retain
// all protected runtime handles until this connection is destroyed.
extern "C" void* openrdx_local_trust_open();
extern "C" void openrdx_local_trust_close(void* lease);
extern "C" std::uint8_t openrdx_local_trust_service_sid(std::uint32_t pid);

namespace {

using namespace openrdx::windows_io;

static_assert(sizeof(char16_t) == sizeof(wchar_t));

constexpr wchar_t kPipeName[] = LR"(\\.\pipe\OpenRDXHardwareService)";
constexpr wchar_t kServiceName[] = L"OpenRDXHardwareService";
constexpr wchar_t kServiceArguments[] =
    L" --service-mode named-pipe --protocol-version 1";
constexpr DWORD kClientAccess = FILE_READ_DATA | FILE_WRITE_DATA |
                                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
                                SYNCHRONIZE;
constexpr DWORD kServiceControlAccess =
    SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START;
constexpr DWORD kServicePollMs = 50;
constexpr DWORD kServiceStartTimeoutMs = 5'000;
constexpr DWORD kNativeActivationTimeoutMs = 7'000;


struct ScopedService {
  SC_HANDLE value = nullptr;
  ~ScopedService() {
    if (value != nullptr) CloseServiceHandle(value);
  }
};

enum class EventKind { kConnected, kData, kError, kClosed };

struct Event {
  EventKind kind;
  std::vector<std::uint8_t> data;
  const char* reason = nullptr;
};

struct Connection {
  napi_env env = nullptr;
  napi_ref wrapper = nullptr;
  napi_threadsafe_function events = nullptr;
  std::wstring expected_executable;
  std::shared_ptr<void> trust;
  std::atomic<bool> closing{false};
  std::atomic<bool> wrapped{false};
  std::atomic<HANDLE> pipe{INVALID_HANDLE_VALUE};
  ScopedHandle stop_event;
  std::mutex write_mutex;
  std::thread worker;
};

struct ServiceConfigSnapshot {
  DWORD service_type = 0;
  DWORD start_type = 0;
  DWORD service_sid_type = 0;
  DWORD error_control = 0;
  DWORD tag = 0;
  std::wstring binary_path;
  std::wstring load_order_group;
  std::vector<std::wstring> dependencies;
  std::wstring account;
  std::wstring display_name;

  bool operator==(const ServiceConfigSnapshot&) const = default;
};

struct FileIdentity {
  DWORD volume = 0;
  DWORD index_high = 0;
  DWORD index_low = 0;

  bool operator==(const FileIdentity&) const = default;
};


bool NapiOk(napi_status status) { return status == napi_ok; }


bool IsTransientPipeAvailabilityError(DWORD error) {
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PIPE_BUSY ||
         error == ERROR_SEM_TIMEOUT;
}


void Emit(Connection* connection, std::unique_ptr<Event> event) {
  if (napi_call_threadsafe_function(connection->events, event.release(),
                                    napi_tsfn_nonblocking) != napi_ok) {
    connection->closing.store(true, std::memory_order_release);
    SetEvent(connection->stop_event.value);
  }
}

void CallJs(napi_env env, napi_value callback, void*, void* raw_event) {
  std::unique_ptr<Event> event(static_cast<Event*>(raw_event));
  if (env == nullptr || callback == nullptr) return;
  napi_value object;
  napi_value type;
  if (!NapiOk(napi_create_object(env, &object))) return;
  const char* type_text = "error";
  switch (event->kind) {
    case EventKind::kConnected: type_text = "connect"; break;
    case EventKind::kData: type_text = "data"; break;
    case EventKind::kClosed: type_text = "close"; break;
    case EventKind::kError: break;
  }
  if (!NapiOk(napi_create_string_utf8(env, type_text, NAPI_AUTO_LENGTH, &type)) ||
      !NapiOk(napi_set_named_property(env, object, "type", type))) return;
  if (event->kind == EventKind::kData) {
    napi_value bytes;
    if (!NapiOk(napi_create_buffer_copy(env, event->data.size(), event->data.data(),
                                        nullptr, &bytes)) ||
        !NapiOk(napi_set_named_property(env, object, "data", bytes))) return;
  }
  if (event->reason != nullptr) {
    napi_value reason;
    if (!NapiOk(napi_create_string_utf8(env, event->reason, NAPI_AUTO_LENGTH,
                                        &reason)) ||
        !NapiOk(napi_set_named_property(env, object, "reason", reason))) return;
  }
  napi_value undefined;
  napi_get_undefined(env, &undefined);
  napi_call_function(env, undefined, callback, 1, &object, nullptr);
}

void FinalizeEvents(napi_env env, void* data, void*) {
  auto* connection = static_cast<Connection*>(data);
  if (connection->wrapper != nullptr) {
    napi_delete_reference(env, connection->wrapper);
    connection->wrapper = nullptr;
  } else if (!connection->wrapped.load(std::memory_order_acquire)) {
    delete connection;
  }
}

bool SameFileIdentity(const std::wstring& left, const std::wstring& right) {
  ScopedHandle left_file{CreateFileW(left.c_str(), FILE_READ_ATTRIBUTES,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE |
                                         FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL, nullptr)};
  ScopedHandle right_file{CreateFileW(right.c_str(), FILE_READ_ATTRIBUTES,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE |
                                          FILE_SHARE_DELETE,
                                      nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr)};
  if (left_file.value == INVALID_HANDLE_VALUE ||
      right_file.value == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION left_info{};
  BY_HANDLE_FILE_INFORMATION right_info{};
  return GetFileInformationByHandle(left_file.value, &left_info) &&
         GetFileInformationByHandle(right_file.value, &right_info) &&
         left_info.dwVolumeSerialNumber == right_info.dwVolumeSerialNumber &&
         left_info.nFileIndexHigh == right_info.nFileIndexHigh &&
         left_info.nFileIndexLow == right_info.nFileIndexLow;
}

bool ReadFileIdentity(HANDLE file, FileIdentity* identity) {
  BY_HANDLE_FILE_INFORMATION information{};
  if (!GetFileInformationByHandle(file, &information)) return false;
  *identity = FileIdentity{information.dwVolumeSerialNumber,
                           information.nFileIndexHigh,
                           information.nFileIndexLow};
  return true;
}

bool PathMatchesFileIdentity(const std::wstring& path,
                             const FileIdentity& expected_identity) {
  ScopedHandle file{CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE |
                                    FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                                nullptr)};
  FileIdentity actual_identity;
  return file.value != INVALID_HANDLE_VALUE &&
         ReadFileIdentity(file.value, &actual_identity) &&
         actual_identity == expected_identity;
}

bool ProcessIsLocalServiceAndExactFile(DWORD pid,
                                       const std::wstring& expected) {
  ScopedHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
  if (process.value == nullptr) return false;
  std::vector<wchar_t> path(32'768);
  DWORD path_length = static_cast<DWORD>(path.size());
  if (!QueryFullProcessImageNameW(process.value, 0, path.data(), &path_length) ||
      path_length == 0 || path_length >= static_cast<DWORD>(path.size())) return false;
  if (!SameFileIdentity(std::wstring(path.data(), path_length), expected)) return false;
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(process.value, TOKEN_QUERY, &raw_token)) return false;
  ScopedHandle token{raw_token};
  DWORD bytes = 0;
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
  if (bytes < static_cast<DWORD>(sizeof(TOKEN_USER)) || bytes > 4096) return false;
  std::vector<std::uint8_t> buffer(bytes);
  if (!GetTokenInformation(token.value, TokenUser, buffer.data(), bytes, &bytes))
    return false;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  return IsWellKnownSid(user->User.Sid, WinLocalServiceSid) != FALSE &&
         openrdx_local_trust_service_sid(pid) == 1;
}

bool CopyBoundedString(const wchar_t* input, const std::uint8_t* begin,
                       DWORD bytes, std::wstring* output) {
  if (input == nullptr) {
    output->clear();
    return true;
  }
  const auto* pointer = reinterpret_cast<const std::uint8_t*>(input);
  const auto* end = begin + bytes;
  if (pointer < begin || pointer >= end ||
      reinterpret_cast<std::uintptr_t>(pointer) % alignof(wchar_t) != 0)
    return false;
  const size_t available = static_cast<size_t>(end - pointer) / sizeof(wchar_t);
  size_t length = 0;
  while (length < available && input[length] != L'\0') ++length;
  if (length == available) return false;
  output->assign(input, length);
  return true;
}

bool CopyBoundedMultiString(const wchar_t* input, const std::uint8_t* begin,
                            DWORD bytes, std::vector<std::wstring>* output) {
  output->clear();
  if (input == nullptr) return true;
  const auto* pointer = reinterpret_cast<const std::uint8_t*>(input);
  const auto* end = begin + bytes;
  if (pointer < begin || pointer >= end ||
      reinterpret_cast<std::uintptr_t>(pointer) % alignof(wchar_t) != 0)
    return false;
  size_t remaining = static_cast<size_t>(end - pointer) / sizeof(wchar_t);
  while (remaining > 0 && *input != L'\0') {
    size_t length = 0;
    while (length < remaining && input[length] != L'\0') ++length;
    if (length == remaining || output->size() >= 64) return false;
    output->emplace_back(input, length);
    input += length + 1;
    remaining -= length + 1;
  }
  return remaining > 0;
}

bool QueryServiceSnapshot(SC_HANDLE service, SERVICE_STATUS_PROCESS* status,
                          ServiceConfigSnapshot* snapshot) {
  DWORD returned = 0;
  if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(status), sizeof(*status),
                            &returned) ||
      returned != static_cast<DWORD>(sizeof(*status))) return false;
  DWORD needed = 0;
  QueryServiceConfigW(service, nullptr, 0, &needed);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
      needed < static_cast<DWORD>(sizeof(QUERY_SERVICE_CONFIGW)) ||
      needed > 65'536) return false;
  const size_t units =
      (needed + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t);
  std::vector<std::max_align_t> storage(units);
  auto* bytes = reinterpret_cast<std::uint8_t*>(storage.data());
  auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
  if (!QueryServiceConfigW(service, config, needed, &needed)) return false;
  SERVICE_SID_INFO sid_info{};
  DWORD sid_bytes = 0;
  if (!QueryServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO,
                           reinterpret_cast<BYTE*>(&sid_info), sizeof(sid_info),
                           &sid_bytes)) return false;
  snapshot->service_sid_type = sid_info.dwServiceSidType;
  snapshot->service_type = config->dwServiceType;
  snapshot->start_type = config->dwStartType;
  snapshot->error_control = config->dwErrorControl;
  snapshot->tag = config->dwTagId;
  return CopyBoundedString(config->lpBinaryPathName, bytes, needed,
                           &snapshot->binary_path) &&
         CopyBoundedString(config->lpLoadOrderGroup, bytes, needed,
                           &snapshot->load_order_group) &&
         CopyBoundedMultiString(config->lpDependencies, bytes, needed,
                                &snapshot->dependencies) &&
         CopyBoundedString(config->lpServiceStartName, bytes, needed,
                           &snapshot->account) &&
         CopyBoundedString(config->lpDisplayName, bytes, needed,
                           &snapshot->display_name);
}

bool ImmutableServiceConfigMatches(const ServiceConfigSnapshot& config,
                                   const std::wstring& expected,
                                   const FileIdentity& expected_identity);
bool RunningServiceSnapshotMatches(const SERVICE_STATUS_PROCESS& status,
                                   const ServiceConfigSnapshot& config,
                                   const std::wstring& expected,
                                   const FileIdentity& expected_identity);

bool ServiceSnapshotMatches(const SERVICE_STATUS_PROCESS& status,
                            const ServiceConfigSnapshot& config,
                            DWORD pipe_pid, const std::wstring& expected) {
  if (status.dwCurrentState != SERVICE_RUNNING ||
      status.dwServiceType != SERVICE_WIN32_OWN_PROCESS ||
      status.dwProcessId == 0 || status.dwProcessId != pipe_pid) return false;
  ScopedHandle expected_file{CreateFileW(
      expected.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
  FileIdentity expected_identity;
  return expected_file.value != INVALID_HANDLE_VALUE &&
         ReadFileIdentity(expected_file.value, &expected_identity) &&
         ImmutableServiceConfigMatches(config, expected, expected_identity);
}

bool VerifyServer(HANDLE pipe, const std::wstring& expected) {
  ULONG pipe_pid = 0;
  if (!GetNamedPipeServerProcessId(pipe, &pipe_pid) || pipe_pid == 0) return false;
  ScopedService manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
  if (manager.value == nullptr) return false;
  ScopedService service{OpenServiceW(manager.value, kServiceName,
                                    SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)};
  if (service.value == nullptr) return false;
  SERVICE_STATUS_PROCESS first_status{};
  SERVICE_STATUS_PROCESS second_status{};
  ServiceConfigSnapshot first_config;
  ServiceConfigSnapshot second_config;
  if (!QueryServiceSnapshot(service.value, &first_status, &first_config) ||
      !ServiceSnapshotMatches(first_status, first_config, pipe_pid, expected) ||
      !ProcessIsLocalServiceAndExactFile(pipe_pid, expected) ||
      !QueryServiceSnapshot(service.value, &second_status, &second_config) ||
      !ServiceSnapshotMatches(second_status, second_config, pipe_pid, expected))
    return false;
  return first_status.dwProcessId == second_status.dwProcessId &&
         first_status.dwCurrentState == second_status.dwCurrentState &&
         first_config == second_config;
}

const char* EnsureServiceRunning(const std::wstring& expected,
                                 ULONGLONG activation_deadline) {
  ScopedService manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
  if (manager.value == nullptr) return "insufficient-permission";
  ScopedService service{
      OpenServiceW(manager.value, kServiceName, kServiceControlAccess)};
  if (service.value == nullptr) {
    const DWORD error = GetLastError();
    return error == ERROR_SERVICE_DOES_NOT_EXIST ? "service-not-installed"
           : error == ERROR_ACCESS_DENIED       ? "insufficient-permission"
                                                : "service-exited";
  }

  ScopedHandle expected_file{CreateFileW(
      expected.c_str(), FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
  FileIdentity expected_identity;
  if (expected_file.value == INVALID_HANDLE_VALUE ||
      !ReadFileIdentity(expected_file.value, &expected_identity))
    return "service-identity-unverified";

  ServiceConfigSnapshot baseline_config;
  bool baseline_set = false;
  bool start_requested = false;
  const ULONGLONG service_start_deadline =
      std::min<ULONGLONG>(activation_deadline,
                          DeadlineAfter(kServiceStartTimeoutMs));
  for (;;) {
    SERVICE_STATUS_PROCESS status{};
    ServiceConfigSnapshot config;
    if (!QueryServiceSnapshot(service.value, &status, &config))
      return "service-exited";
    if (!ImmutableServiceConfigMatches(config, expected, expected_identity) ||
        (baseline_set && !(baseline_config == config)))
      return "service-identity-unverified";
    if (!baseline_set) {
      baseline_config = config;
      baseline_set = true;
    }

    if (status.dwCurrentState == SERVICE_RUNNING) {
      SERVICE_STATUS_PROCESS confirmation{};
      ServiceConfigSnapshot confirmation_config;
      if (!RunningServiceSnapshotMatches(status, config, expected,
                                         expected_identity) ||
          !QueryServiceSnapshot(service.value, &confirmation,
                                &confirmation_config) ||
          status.dwProcessId != confirmation.dwProcessId ||
          status.dwCurrentState != confirmation.dwCurrentState ||
          !(config == confirmation_config) ||
          !RunningServiceSnapshotMatches(confirmation, confirmation_config,
                                         expected, expected_identity))
        return "service-identity-unverified";
      return nullptr;
    }

    if (status.dwCurrentState == SERVICE_STOPPED) {
      if (start_requested) return "service-exited";
      if (!StartServiceW(service.value, 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING)
          return error == ERROR_ACCESS_DENIED ? "insufficient-permission"
                                              : "service-exited";
      }
      start_requested = true;
    } else if (status.dwCurrentState != SERVICE_START_PENDING &&
               status.dwCurrentState != SERVICE_STOP_PENDING) {
      return "service-exited";
    }

    const DWORD delay =
        RemainingMilliseconds(service_start_deadline, kServicePollMs);
    if (delay == 0) return "service-exited";
    Sleep(delay);
  }
}

bool ImmutableServiceConfigMatches(const ServiceConfigSnapshot& config,
                                   const std::wstring& expected,
                                   const FileIdentity& expected_identity) {
  const std::wstring exact_command = L"\"" + expected + L"\"" + kServiceArguments;
  return config.service_type == SERVICE_WIN32_OWN_PROCESS &&
         config.start_type == SERVICE_DEMAND_START &&
         config.service_sid_type == SERVICE_SID_TYPE_UNRESTRICTED &&
         config.error_control == SERVICE_ERROR_NORMAL && config.tag == 0 &&
         config.binary_path == exact_command && config.load_order_group.empty() &&
         config.dependencies.empty() &&
         config.account == L"NT AUTHORITY\\LocalService" &&
         config.display_name == L"OpenRDX Hardware Service" &&
         PathMatchesFileIdentity(expected, expected_identity);
}

bool RunningServiceSnapshotMatches(const SERVICE_STATUS_PROCESS& status,
                                   const ServiceConfigSnapshot& config,
                                   const std::wstring& expected,
                                   const FileIdentity& expected_identity) {
  return status.dwCurrentState == SERVICE_RUNNING &&
         status.dwServiceType == SERVICE_WIN32_OWN_PROCESS &&
         status.dwProcessId != 0 &&
         ImmutableServiceConfigMatches(config, expected, expected_identity) &&
         ProcessIsLocalServiceAndExactFile(status.dwProcessId, expected);
}

HANDLE OpenVerifiedPipe(const std::wstring& expected, HANDLE stop_event, const char** reason) {
  const ULONGLONG activation_deadline =
      DeadlineAfter(kNativeActivationTimeoutMs);
  if (const char* activation_failure =
          EnsureServiceRunning(expected, activation_deadline);
      activation_failure != nullptr) {
    *reason = activation_failure;
    return INVALID_HANDLE_VALUE;
  }

  for (;;) {
    const DWORD wait =
        RemainingMilliseconds(activation_deadline, kServicePollMs);
    if (wait == 0) {
      *reason = "service-exited";
      return INVALID_HANDLE_VALUE;
    }
    if (!WaitNamedPipeW(kPipeName, wait)) {
      const DWORD error = GetLastError();
      if (error == ERROR_ACCESS_DENIED) {
        *reason = "insufficient-permission";
        return INVALID_HANDLE_VALUE;
      }
      if (!IsTransientPipeAvailabilityError(error)) {
        *reason = "service-exited";
        return INVALID_HANDLE_VALUE;
      }
      if (error == ERROR_FILE_NOT_FOUND) Sleep(wait);
      continue;
    }

    HANDLE pipe = CreateFileW(
        kPipeName, kClientAccess, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      if (error == ERROR_ACCESS_DENIED) {
        *reason = "insufficient-permission";
        return INVALID_HANDLE_VALUE;
      }
      if (IsTransientPipeAvailabilityError(error)) continue;
      *reason = "service-exited";
      return INVALID_HANDLE_VALUE;
    }
    if (!VerifyServer(pipe, expected)) {
      CloseHandle(pipe);
      *reason = "service-identity-unverified";
      return INVALID_HANDLE_VALUE;
    }
    // Peer proof keeps its original activation deadline. The service separately
    // re-verifies the complete runtime before accepting and preparing a session;
    // that disk work must not consume the seven-second peer-proof allowance.
    if (RemainingMilliseconds(activation_deadline, 1) == 0 ||
        !ReadServiceReadyAfterProof(pipe, stop_event)) {
      CloseHandle(pipe);
      *reason = "service-exited";
      return INVALID_HANDLE_VALUE;
    }
    return pipe;
  }
}

void Worker(Connection* connection) {
  const char* failure = nullptr;
  connection->trust = std::shared_ptr<void>(openrdx_local_trust_open(),
                                             openrdx_local_trust_close);
  HANDLE pipe = INVALID_HANDLE_VALUE;
  if (connection->trust) {
    pipe = OpenVerifiedPipe(connection->expected_executable, connection->stop_event.value, &failure);
  } else {
    failure = "service-identity-unverified";
  }
  if (pipe == INVALID_HANDLE_VALUE) {
    connection->trust.reset();
    Emit(connection, std::make_unique<Event>(Event{EventKind::kError, {}, failure}));
    connection->closing.store(true, std::memory_order_release);
    Emit(connection, std::make_unique<Event>(Event{EventKind::kClosed, {}, nullptr}));
    napi_release_threadsafe_function(connection->events, napi_tsfn_release);
    return;
  }
  connection->pipe.store(pipe, std::memory_order_release);
  if (!connection->closing.load(std::memory_order_acquire))
    Emit(connection, std::make_unique<Event>(Event{EventKind::kConnected, {}, nullptr}));
  while (failure == nullptr &&
         !connection->closing.load(std::memory_order_acquire)) {
    std::unique_ptr<PendingIo> operation;
    if (!CreatePendingIo(65'540, &operation)) {
      failure = "service-exited";
      break;
    }
    if (!DuplicateIoHandle(pipe, operation.get())) {
      failure = "service-exited";
      break;
    }
    DWORD read = 0;
    BOOL completed =
        ReadFile(operation->pipe.value, operation->storage.data(),
                 static_cast<DWORD>(operation->storage.size()), &read,
                 &operation->overlapped);
    if (!completed && GetLastError() == ERROR_IO_PENDING) {
      HANDLE waits[] = {operation->event.value, connection->stop_event.value};
      DWORD wait = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
      if (wait == WAIT_OBJECT_0 + 1) {
        CancelAndDrainPendingIo(&operation);
        break;
      }
      bool read_succeeded = false;
      const bool read_terminal =
          wait == WAIT_OBJECT_0 && ObservePendingIoTerminal(
                                       operation.get(), &read, &read_succeeded);
      if (!read_terminal || !read_succeeded) {
        if (!read_terminal) CancelAndDrainPendingIo(&operation);
        failure = "service-exited";
        break;
      }
    } else if (!completed) {
      failure = "service-exited";
      break;
    }
    if (read == 0) break;
    operation->storage.resize(read);
    Event event{EventKind::kData, {}, nullptr};
    event.data = std::move(operation->storage);
    Emit(connection, std::make_unique<Event>(std::move(event)));
  }
  {
    std::lock_guard<std::mutex> lock(connection->write_mutex);
    connection->pipe.store(INVALID_HANDLE_VALUE, std::memory_order_release);
    // All I/O is issued on operation-owned duplicates. Once the write mutex is
    // held, the authoritative connection handle has no pending operations.
    CloseHandle(pipe);
  }
  if (failure != nullptr &&
      !connection->closing.load(std::memory_order_acquire)) {
    Emit(connection, std::make_unique<Event>(Event{EventKind::kError, {}, failure}));
  }
  connection->trust.reset();
  connection->closing.store(true, std::memory_order_release);
  Emit(connection, std::make_unique<Event>(Event{EventKind::kClosed, {}, nullptr}));
  napi_release_threadsafe_function(connection->events, napi_tsfn_release);
}

Connection* Unwrap(napi_env env, napi_callback_info info, napi_value* this_value,
                   size_t* argc = nullptr, napi_value* argv = nullptr) {
  size_t count = argc == nullptr ? 0 : *argc;
  if (!NapiOk(napi_get_cb_info(env, info, &count, argv, this_value, nullptr)))
    return nullptr;
  if (argc != nullptr) *argc = count;
  Connection* connection = nullptr;
  if (!NapiOk(napi_unwrap(env, *this_value,
                          reinterpret_cast<void**>(&connection)))) return nullptr;
  return connection;
}

napi_value Destroy(napi_env env, napi_callback_info info) {
  napi_value self;
  Connection* connection = Unwrap(env, info, &self);
  if (connection != nullptr &&
      !connection->closing.exchange(true, std::memory_order_acq_rel)) {
    SetEvent(connection->stop_event.value);
  }
  return self;
}

napi_value Write(napi_env env, napi_callback_info info) {
  napi_value self;
  napi_value argv[1];
  size_t argc = 1;
  Connection* connection = Unwrap(env, info, &self, &argc, argv);
  bool is_buffer = false;
  void* bytes = nullptr;
  size_t length = 0;
  if (connection == nullptr || argc != 1 ||
      !NapiOk(napi_is_buffer(env, argv[0], &is_buffer)) || !is_buffer ||
      !NapiOk(napi_get_buffer_info(env, argv[0], &bytes, &length)) ||
      length == 0 || length > kMaxFrameStorage ||
      connection->closing.load(std::memory_order_acquire)) {
    napi_value result;
    napi_get_boolean(env, false, &result);
    return result;
  }
  std::lock_guard<std::mutex> lock(connection->write_mutex);
  HANDLE pipe = connection->pipe.load(std::memory_order_acquire);
  std::unique_ptr<PendingIo> operation;
  if (!CreatePendingIo(length, &operation)) {
    napi_value result;
    napi_get_boolean(env, false, &result);
    return result;
  }
  std::memcpy(operation->storage.data(), bytes, length);
  if (!DuplicateIoHandle(pipe, operation.get())) {
    napi_value result;
    napi_get_boolean(env, false, &result);
    return result;
  }
  DWORD written = 0;
  BOOL completed = WriteFile(operation->pipe.value, operation->storage.data(),
                             static_cast<DWORD>(length), &written,
                             &operation->overlapped);
  bool succeeded = completed != FALSE;
  if (!succeeded && GetLastError() == ERROR_IO_PENDING) {
    HANDLE waits[] = {operation->event.value, connection->stop_event.value};
    DWORD wait = WaitForMultipleObjects(2, waits, FALSE, kIoTimeoutMs);
    bool write_succeeded = false;
    const bool write_terminal =
        wait == WAIT_OBJECT_0 && ObservePendingIoTerminal(
                                     operation.get(), &written,
                                     &write_succeeded);
    succeeded = write_terminal && write_succeeded &&
                written == static_cast<DWORD>(length);
    if (!write_terminal) CancelAndDrainPendingIo(&operation);
  }
  napi_value result;
  napi_get_boolean(env, succeeded && written == static_cast<DWORD>(length), &result);
  return result;
}

void FinalizeConnection(napi_env, void* data, void*) {
  auto* connection = static_cast<Connection*>(data);
  connection->closing.store(true, std::memory_order_release);
  SetEvent(connection->stop_event.value);
  if (connection->worker.joinable()) connection->worker.join();
  delete connection;
}

bool ReadStrictAbsolutePath(napi_env env, napi_value value, std::wstring* output) {
  napi_valuetype type;
  if (!NapiOk(napi_typeof(env, value, &type)) || type != napi_string) return false;
  size_t length = 0;
  if (!NapiOk(napi_get_value_string_utf16(env, value, nullptr, 0, &length)) ||
      length < 4 || length > 32'000) return false;
  std::vector<char16_t> units(length + 1);
  if (!NapiOk(napi_get_value_string_utf16(env, value, units.data(), units.size(),
                                          &length))) return false;
  output->assign(reinterpret_cast<const wchar_t*>(units.data()), length);
  return output->size() >= 3 && (*output)[1] == L':' &&
         ((*output)[2] == L'\\' || (*output)[2] == L'/') &&
         output->find(L'"') == std::wstring::npos &&
         output->find(L'\n') == std::wstring::npos &&
         output->find(L'\r') == std::wstring::npos;
}

napi_value Connect(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  size_t argc = 2;
  napi_value unused;
  napi_get_cb_info(env, info, &argc, argv, &unused, nullptr);
  napi_valuetype callback_type;
  std::wstring expected;
  if (argc != 2 || !ReadStrictAbsolutePath(env, argv[0], &expected) ||
      !NapiOk(napi_typeof(env, argv[1], &callback_type)) ||
      callback_type != napi_function) {
    napi_throw_type_error(env, nullptr, "windows-client-arguments-invalid");
    return nullptr;
  }
  auto connection = std::make_unique<Connection>();
  connection->env = env;
  connection->expected_executable = std::move(expected);
  connection->stop_event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (connection->stop_event.value == nullptr) {
    napi_throw_error(env, nullptr, "windows-client-resource-failed");
    return nullptr;
  }
  napi_value resource_name;
  napi_value object;
  napi_create_string_utf8(env, "OpenRDXWindowsPipe", NAPI_AUTO_LENGTH,
                          &resource_name);
  napi_create_object(env, &object);
  if (!NapiOk(napi_create_threadsafe_function(
          env, argv[1], nullptr, resource_name, 64, 1, connection.get(),
          FinalizeEvents, nullptr, CallJs, &connection->events))) {
    napi_throw_error(env, nullptr, "windows-client-resource-failed");
    return nullptr;
  }
  Connection* raw = connection.release();
  if (!NapiOk(napi_wrap(env, object, raw, FinalizeConnection, nullptr, nullptr))) {
    napi_release_threadsafe_function(raw->events, napi_tsfn_abort);
    napi_throw_error(env, nullptr, "windows-client-resource-failed");
    return nullptr;
  }
  raw->wrapped.store(true, std::memory_order_release);
  if (!NapiOk(napi_create_reference(env, object, 1, &raw->wrapper))) {
    napi_release_threadsafe_function(raw->events, napi_tsfn_abort);
    napi_throw_error(env, nullptr, "windows-client-resource-failed");
    return nullptr;
  }
  napi_property_descriptor methods[] = {
      {"write", nullptr, Write, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"destroy", nullptr, Destroy, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"end", nullptr, Destroy, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (!NapiOk(napi_define_properties(env, object, 3, methods))) {
    napi_release_threadsafe_function(raw->events, napi_tsfn_abort);
    napi_throw_error(env, nullptr, "windows-client-resource-failed");
    return nullptr;
  }
  try {
    raw->worker = std::thread(Worker, raw);
  } catch (...) {
    napi_release_threadsafe_function(raw->events, napi_tsfn_abort);
    napi_throw_error(env, nullptr, "windows-client-resource-failed");
    return nullptr;
  }
  return object;
}

/** Resolves only the fixed Windows backup folder; no caller path is accepted. */
napi_value ManufacturingBackupDirectory(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argument;
  if (napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr) != napi_ok || argc != 0) {
    napi_throw_type_error(env, nullptr, "manufacturing-folder-arguments-invalid");
    return nullptr;
  }
  PWSTR path = nullptr;
  if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, KF_FLAG_DEFAULT, nullptr, &path))) {
    napi_throw_error(env, nullptr, "manufacturing-folder-unavailable");
    return nullptr;
  }
  const std::wstring directory = std::wstring(path) + L"\\OpenRDXManager\\manufacturing-backups";
  CoTaskMemFree(path);
  napi_value value;
  if (napi_create_string_utf16(env, reinterpret_cast<const char16_t*>(directory.data()), directory.size(), &value) != napi_ok) return nullptr;
  return value;
}

/** Registers closed main-process native helpers without exposing raw OS handles. */
napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor function = {
      "connect", nullptr, Connect, nullptr, nullptr, nullptr, napi_default, nullptr};
  napi_define_properties(env, exports, 1, &function);
  napi_property_descriptor folder = {"manufacturingBackupDirectory", nullptr, ManufacturingBackupDirectory,
      nullptr, nullptr, nullptr, napi_default, nullptr};
  napi_define_properties(env, exports, 1, &folder);
  if (openrdx::logs::RegisterLogFiles(env, exports) != napi_ok) {
    napi_throw_error(env, nullptr, "windows-log-binding-failed");
    return nullptr;
  }
  return exports;
}

}  // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
