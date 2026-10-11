// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "windows_mcp_files.h"
#include <objbase.h>
#include <cstring>

namespace openrdx::logs {
namespace {
constexpr size_t kSettingsLimit = 4096, kTokenLength = 65;

/** Returns a fixed MCP basename without accepting arbitrary path components. */
const wchar_t* Name(bool token) { return token ? L"token" : L"settings.json"; }

/** Maps absence/collision only; native details and credentials stay private. */
[[noreturn]] void McpIoFailure() {
  const auto error = GetLastError();
  throw Failure{error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? "ENOENT" :
                error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS ? "EEXIST" :
                "windows-mcp-io-failed"};
}

/** Validates the exact random-token representation before persistence or use. */
bool ValidToken(const std::vector<std::uint8_t>& value) {
  if ((value.size() != 64 && value.size() != kTokenLength) ||
      (value.size() == kTokenLength && value.back() != '\n')) return false;
  for (size_t index = 0; index < 64; ++index)
    if (!((value[index] >= 'a' && value[index] <= 'f') ||
          (value[index] >= '0' && value[index] <= '9'))) return false;
  return true;
}

/** Writes all bytes to a newly owned handle and flushes before publication. */
void WriteAll(HANDLE handle, const std::vector<std::uint8_t>& bytes) {
  size_t offset = 0;
  while (offset < bytes.size()) {
    DWORD written = 0;
    if (!WriteFile(handle, bytes.data() + offset,
                   static_cast<DWORD>(bytes.size() - offset), &written, nullptr) || !written)
      McpIoFailure();
    offset += written;
  }
  if (!FlushFileBuffers(handle)) McpIoFailure();
}

/** Removes only this invocation's newly created file if publication fails. */
struct Pending {
  Handle handle;
  bool published = false;
  /** Deletes by owned handle, never by a caller-derived filename. */
  ~Pending() {
    if (!published && handle.get() != INVALID_HANDLE_VALUE) {
      FILE_DISPOSITION_INFO disposition{TRUE};
      SetFileInformationByHandle(handle.get(), FileDispositionInfo, &disposition, sizeof(disposition));
    }
  }
};
}  // namespace

McpStore::McpStore(std::wstring path) : root_(std::make_shared<Root>(std::move(path))) {}

void McpStore::prepare() {
  std::lock_guard lock(mutex_);
  root_->prepare();
}

Handle McpStore::open(const Directory& directory, bool token, DWORD access, DWORD sharing) {
  const auto path = directory.path + L"\\" + Name(token);
  Handle file(CreateFileW(path.c_str(), access | READ_CONTROL | FILE_READ_ATTRIBUTES,
                          sharing, nullptr, OPEN_EXISTING,
                          FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (file.get() == INVALID_HANDLE_VALUE) McpIoFailure();
  // In particular, do not repair and read a credential whose privacy is unproven.
  root_->verify(file.get(), false, false);
  return file;
}

std::vector<std::uint8_t> McpStore::read_handle(HANDLE handle, size_t maximum) {
  const auto info = root_->verify(handle, false, false);
  if (info.nFileSizeHigh || info.nFileSizeLow > maximum)
    throw Failure{"windows-mcp-file-too-large"};
  LARGE_INTEGER start{};
  if (!SetFilePointerEx(handle, start, nullptr, FILE_BEGIN)) McpIoFailure();
  std::vector<std::uint8_t> bytes(maximum + 1);
  DWORD count = 0;
  if (!ReadFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr)) {
    SecureZeroMemory(bytes.data(), bytes.size());
    McpIoFailure();
  }
  if (count > maximum) {
    SecureZeroMemory(bytes.data(), bytes.size());
    throw Failure{"windows-mcp-file-too-large"};
  }
  bytes.resize(count);
  return bytes;
}

std::vector<std::uint8_t> McpStore::read_locked(bool token) {
  auto directory = root_->pin(false);
  auto file = open(directory, token, GENERIC_READ, FILE_SHARE_READ);
  auto bytes = read_handle(file.get(), token ? kTokenLength : kSettingsLimit);
  if (token && !ValidToken(bytes)) {
    SecureZeroMemory(bytes.data(), bytes.size());
    throw Failure{"invalid-mcp-token"};
  }
  return bytes;
}

std::vector<std::uint8_t> McpStore::read(bool token) {
  std::lock_guard lock(mutex_);
  return read_locked(token);
}

void McpStore::write_settings(const std::vector<std::uint8_t>& bytes) {
  std::lock_guard lock(mutex_);
  if (bytes.empty() || bytes.size() > kSettingsLimit)
    throw Failure{"windows-mcp-arguments-invalid"};
  auto directory = root_->pin(false);
  Handle previous;
  try { previous = open(directory, false, 0, FILE_SHARE_READ | FILE_SHARE_DELETE); }
  catch (const Failure& failure) { if (std::strcmp(failure.code, "ENOENT") != 0) throw; }
  GUID id{};
  wchar_t text[40]{};
  if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, text, 40))
    throw Failure{"windows-mcp-resource-failed"};
  const auto temporary = directory.path + L"\\.mcp-settings-" + text + L".tmp";
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), root_->security_, FALSE};
  Pending pending;
  pending.handle = Handle(CreateFileW(temporary.c_str(),
      GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE,
      0, &attributes, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
  if (pending.handle.get() == INVALID_HANDLE_VALUE) McpIoFailure();
  root_->verify(pending.handle.get(), false, false);
  WriteAll(pending.handle.get(), bytes);
  if (read_handle(pending.handle.get(), kSettingsLimit) != bytes)
    throw Failure{"windows-mcp-readback-failed"};
  RenamePinnedFile(pending.handle.get(), directory, RenameDestination::McpSettings,
                   previous.get() != INVALID_HANDLE_VALUE);
  pending.published = true;
}

std::vector<std::uint8_t> McpStore::ensure_token(const std::vector<std::uint8_t>& proposed) {
  std::lock_guard lock(mutex_);
  if (!ValidToken(proposed)) throw Failure{"invalid-mcp-token"};
  auto directory = root_->pin(false);
  const auto path = directory.path + L"\\token";
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), root_->security_, FALSE};
  Pending pending;
  pending.handle = Handle(CreateFileW(path.c_str(),
      GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE,
      0, &attributes, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
  if (pending.handle.get() == INVALID_HANDLE_VALUE) {
    const auto error = GetLastError();
    if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
      return read_locked(true);
    McpIoFailure();
  }
  root_->verify(pending.handle.get(), false, false);
  WriteAll(pending.handle.get(), proposed);
  auto actual = read_handle(pending.handle.get(), kTokenLength);
  if (actual != proposed) {
    SecureZeroMemory(actual.data(), actual.size());
    throw Failure{"windows-mcp-readback-failed"};
  }
  pending.published = true;
  return actual;
}
}  // namespace openrdx::logs
