// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "windows_log_files.h"

#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <utility>

namespace openrdx::logs {
namespace {

constexpr wchar_t kCurrent[] = L"RDXManager.jsonl";
constexpr wchar_t kBackup[] = L"_RDXManager.bak";

/** Releases buffers allocated by Windows security APIs. */
struct LocalBuffer {
  void* value = nullptr;
  /** Frees the allocation without throwing during unwinding. */
  ~LocalBuffer() { if (value) LocalFree(value); }
};

/** Maps only absence specially; never exposes an OS pathname or diagnostic text. */
[[noreturn]] void IoFailure() {
  const DWORD code = GetLastError();
  throw Failure{code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND
                    ? "ENOENT" : "windows-log-io-failed"};
}

/** Rejects device aliases, streams, traversal and Win32-normalized path components. */
bool ValidComponent(const std::wstring& part) {
  if (part.empty() || part == L"." || part == L".." || part.back() == L'.' ||
      part.back() == L' ' || part.size() > 255) return false;
  for (const wchar_t ch : part) {
    if (ch < 32 || std::wstring(L"<>:\"/\\|?*").find(ch) != std::wstring::npos)
      return false;
  }
  std::wstring stem = part.substr(0, part.find(L'.'));
  std::transform(stem.begin(), stem.end(), stem.begin(), [](wchar_t ch) {
    return ch >= L'a' && ch <= L'z' ? static_cast<wchar_t>(ch - L'a' + L'A') : ch;
  });
  if (stem == L"CON" || stem == L"PRN" || stem == L"AUX" || stem == L"NUL")
    return false;
  return !(stem.size() == 4 && (stem.starts_with(L"COM") || stem.starts_with(L"LPT")) &&
           ((stem[3] >= L'0' && stem[3] <= L'9') || stem[3] == 0xB9 ||
            stem[3] == 0xB2 || stem[3] == 0xB3));
}

/** Queries a bounded volume-GUID pathname, choosing canonical or exact opened spelling. */
std::wstring FinalPath(HANDLE handle, DWORD name_format = FILE_NAME_NORMALIZED) {
  std::vector<wchar_t> buffer(32'768);
  const DWORD length = GetFinalPathNameByHandleW(
      handle, buffer.data(), static_cast<DWORD>(buffer.size()), VOLUME_NAME_GUID | name_format);
  if (!length || length >= buffer.size()) IoFailure();
  return std::wstring(buffer.data(), length);
}

/** Rejects any reparse object, wrong type, or non-regular/multiply-linked file. */
BY_HANDLE_FILE_INFORMATION TypeProof(HANDLE handle, bool directory) {
  BY_HANDLE_FILE_INFORMATION info{};
  if (GetFileType(handle) != FILE_TYPE_DISK ||
      !GetFileInformationByHandle(handle, &info)) IoFailure();
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
      ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
      (!directory && info.nNumberOfLinks != 1))
    throw Failure{"windows-log-unsafe-object"};
  return info;
}

/** Checks the exact protected one-user full-control ACL created by this boundary. */
bool PrivateAcl(PSECURITY_DESCRIPTOR descriptor, PACL acl, PSID user) {
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
      !(control & SE_DACL_PROTECTED) || !acl || !IsValidAcl(acl) || acl->AceCount != 1)
    return false;
  void* raw = nullptr;
  if (!GetAce(acl, 0, &raw)) return false;
  const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
  if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0 ||
      ace->Mask != FILE_ALL_ACCESS || ace->Header.AceSize < sizeof(ACCESS_ALLOWED_ACE))
    return false;
  PSID sid = const_cast<DWORD*>(&ace->SidStart);
  return IsValidSid(sid) && GetLengthSid(sid) <=
      ace->Header.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart) && EqualSid(sid, user);
}

}  // namespace

Handle::Handle(HANDLE value) noexcept : value_(value) {}
Handle::~Handle() { close(); }
Handle::Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
Handle& Handle::operator=(Handle&& other) noexcept {
  if (this != &other) { close(); value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE); }
  return *this;
}
HANDLE Handle::get() const noexcept { return value_; }
void Handle::close() noexcept {
  if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_);
  value_ = INVALID_HANDLE_VALUE;
}

Root::Root(std::wstring path) {
  std::replace(path.begin(), path.end(), L'/', L'\\');
  if (path.size() < 4 || path.size() > 16'000 || path[1] != L':' || path[2] != L'\\' ||
      !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
    throw Failure{"windows-log-path-invalid"};
  drive_ = path.substr(0, 3);
  for (size_t start = 3; start < path.size();) {
    const size_t end = path.find(L'\\', start);
    const std::wstring part = path.substr(start, end == std::wstring::npos ? end : end - start);
    if (!ValidComponent(part)) throw Failure{"windows-log-path-invalid"};
    components_.push_back(part);
    if (end == std::wstring::npos) break;
    start = end + 1;
    if (start == path.size()) throw Failure{"windows-log-path-invalid"};
  }
  if (components_.empty() || components_.size() > 128) throw Failure{"windows-log-path-invalid"};
  HANDLE token_value = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token_value)) IoFailure();
  Handle token(token_value);
  DWORD length = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &length);
  if (!length || length > 65'536) throw Failure{"windows-log-user-unavailable"};
  std::vector<std::uint8_t> token_bytes(length);
  if (!GetTokenInformation(token.get(), TokenUser, token_bytes.data(), length, &length)) IoFailure();
  const auto* user = reinterpret_cast<const TOKEN_USER*>(token_bytes.data());
  if (!IsValidSid(user->User.Sid)) throw Failure{"windows-log-user-unavailable"};
  sid_.resize(GetLengthSid(user->User.Sid));
  if (!CopySid(static_cast<DWORD>(sid_.size()), sid_.data(), user->User.Sid)) IoFailure();
  LocalBuffer sid_text;
  if (!ConvertSidToStringSidW(sid_.data(), reinterpret_cast<LPWSTR*>(&sid_text.value))) IoFailure();
  const std::wstring sid(static_cast<wchar_t*>(sid_text.value));
  const std::wstring sddl = L"O:" + sid + L"D:P(A;;FA;;;" + sid + L")";
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &security_, nullptr)) IoFailure();
}

Root::~Root() { if (security_) LocalFree(security_); }

BY_HANDLE_FILE_INFORMATION Root::verify(HANDLE handle, bool directory, bool harden) const {
  auto info = TypeProof(handle, directory);
  LocalBuffer descriptor;
  PSID owner = nullptr;
  PACL acl = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, nullptr, &acl, nullptr, &descriptor.value) != ERROR_SUCCESS)
    throw Failure{"windows-log-security-unavailable"};
  PSID user = const_cast<std::uint8_t*>(sid_.data());
  if (!owner || !IsValidSid(owner) || !EqualSid(owner, user))
    throw Failure{"windows-log-owner-mismatch"};
  if (!PrivateAcl(descriptor.value, acl, user)) {
    if (!harden) throw Failure{"windows-log-dacl-unverified"};
    BOOL present = FALSE, defaulted = FALSE;
    PACL desired = nullptr;
    if (!GetSecurityDescriptorDacl(security_, &present, &desired, &defaulted) ||
        !present || !desired ||
        SetSecurityInfo(handle, SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, desired, nullptr) != ERROR_SUCCESS)
      throw Failure{"windows-log-dacl-unverified"};
    return verify(handle, directory, false);
  }
  return info;
}

Directory Root::pin(bool create) {
  if (GetDriveTypeW(drive_.c_str()) != DRIVE_FIXED) throw Failure{"windows-log-local-disk-required"};
  Directory pinned;
  // Denying write/delete sharing prevents ancestor replacement or conversion to
  // a junction while subsequent components are resolved.
  Handle volume(CreateFileW(drive_.c_str(), GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  TypeProof(volume.get(), true);
  DWORD flags = 0;
  if (!GetVolumeInformationByHandleW(volume.get(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0) ||
      !(flags & FILE_PERSISTENT_ACLS)) throw Failure{"windows-log-acls-required"};
  pinned.path = FinalPath(volume.get());
  if (!pinned.path.starts_with(L"\\\\?\\Volume{") || pinned.path.back() != L'\\')
    throw Failure{"windows-log-path-unverified"};
  pinned.handles.push_back(std::move(volume));
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), security_, FALSE};
  for (size_t index = 0; index < components_.size(); ++index) {
    const bool final = index + 1 == components_.size();
    if (pinned.path.back() != L'\\') pinned.path += L'\\';
    pinned.path += components_[index];
    const DWORD access = GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES | (final ? WRITE_DAC : 0);
    Handle directory(CreateFileW(pinned.path.c_str(), access, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (directory.get() == INVALID_HANDLE_VALUE && create &&
        (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) {
      if (!CreateDirectoryW(pinned.path.c_str(), &attributes) &&
          GetLastError() != ERROR_ALREADY_EXISTS) IoFailure();
      directory = Handle(CreateFileW(pinned.path.c_str(), access, FILE_SHARE_READ, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
                                      FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    }
    TypeProof(directory.get(), true);
    // FILE_NAME_NORMALIZED expands legitimate 8.3 names such as RUNNER~1.
    // Compare the name actually opened against the exact requested child while
    // the parent is pinned and this no-follow handle has passed TypeProof.
    const std::wstring actual = FinalPath(directory.get(), FILE_NAME_OPENED);
    if (CompareStringOrdinal(actual.c_str(), -1, pinned.path.c_str(), -1, TRUE) != CSTR_EQUAL)
      throw Failure{"windows-log-path-unverified"};
    // Continue from this same handle's canonical spelling so aliases never
    // accumulate in later component resolution or the fixed file paths.
    pinned.path = FinalPath(directory.get());
    if (final) verify(directory.get(), true, create);
    pinned.handles.push_back(std::move(directory));
  }
  return pinned;
}

void Root::prepare() { pin(true); }

Handle Root::open_file(const Directory& directory, bool backup, DWORD access, bool create) {
  const std::wstring path = directory.path + L"\\" + (backup ? kBackup : kCurrent);
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), security_, FALSE};
  // Tightening the directory ACL can remove inherited file access. The owner
  // retains READ_CONTROL/WRITE_DAC, so establish privacy before requesting data
  // access. No file contents are read or written through this metadata handle.
  Handle metadata(CreateFileW(path.c_str(), READ_CONTROL | WRITE_DAC,
                              0, &attributes, create ? OPEN_ALWAYS : OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (metadata.get() == INVALID_HANDLE_VALUE) IoFailure();
  const auto expected = verify(metadata.get(), false, true);
  metadata.close();
  Handle handle(CreateFileW(path.c_str(), access | READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                            0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (handle.get() == INVALID_HANDLE_VALUE) IoFailure();
  // Reopen with no-follow again, and reject replacement or ACL drift before I/O.
  // Ancestors remain pinned across both opens; the data handle never repairs ACLs.
  const auto actual = verify(handle.get(), false, false);
  if (actual.dwVolumeSerialNumber != expected.dwVolumeSerialNumber ||
      actual.nFileIndexHigh != expected.nFileIndexHigh || actual.nFileIndexLow != expected.nFileIndexLow)
    throw Failure{"windows-log-file-replaced"};
  return handle;
}

std::shared_ptr<File> Root::open(bool backup, bool append) {
  if (backup && append) throw Failure{"windows-log-arguments-invalid"};
  auto directory = pin(false);
  auto handle = open_file(directory, backup, append ? GENERIC_WRITE : GENERIC_READ, append);
  return std::make_shared<File>(shared_from_this(), std::move(directory), std::move(handle), append);
}

void Root::remove_backup() {
  auto directory = pin(false);
  Handle file;
  try { file = open_file(directory, true, DELETE, false); }
  catch (const Failure& failure) {
    if (std::strcmp(failure.code, "ENOENT") == 0) return;
    throw;
  }
  FILE_DISPOSITION_INFO disposition{TRUE};
  if (!SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition)))
    IoFailure();
}

void Root::rotate() {
  auto directory = pin(false);
  auto file = open_file(directory, false, DELETE, false);
  const std::wstring expected = directory.path + L"\\" + kBackup;
  RenamePinnedFile(file.get(), directory, RenameDestination::LogBackup, false);
  verify(file.get(), false, false);
  if (CompareStringOrdinal(FinalPath(file.get()).c_str(), -1, expected.c_str(), -1, TRUE) != CSTR_EQUAL)
    throw Failure{"windows-log-rename-unverified"};
}

File::File(std::shared_ptr<Root> root, Directory directory, Handle handle, bool append)
    : root_(std::move(root)), directory_(std::move(directory)), handle_(std::move(handle)), append_(append) {}

std::uint64_t File::size() {
  std::lock_guard lock(mutex_);
  const auto info = root_->verify(handle_.get(), false, false);
  return (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
}

std::vector<std::uint8_t> File::read(size_t length, size_t position) {
  std::lock_guard lock(mutex_);
  if (append_ || length > kMaximumRead || position > kMaximumRead)
    throw Failure{"windows-log-arguments-invalid"};
  root_->verify(handle_.get(), false, false);
  LARGE_INTEGER offset{};
  offset.QuadPart = static_cast<LONGLONG>(position);
  if (!SetFilePointerEx(handle_.get(), offset, nullptr, FILE_BEGIN)) IoFailure();
  std::vector<std::uint8_t> bytes(length);
  DWORD read = 0;
  if (length && !ReadFile(handle_.get(), bytes.data(), static_cast<DWORD>(length), &read, nullptr)) IoFailure();
  bytes.resize(read);
  return bytes;
}

void File::append(const std::vector<std::uint8_t>& bytes) {
  std::lock_guard lock(mutex_);
  if (!append_ || bytes.size() > kMaximumRead) throw Failure{"windows-log-arguments-invalid"};
  root_->verify(handle_.get(), false, false);
  LARGE_INTEGER end{};
  if (!SetFilePointerEx(handle_.get(), end, nullptr, FILE_END)) IoFailure();
  size_t offset = 0;
  while (offset < bytes.size()) {
    DWORD written = 0;
    if (!WriteFile(handle_.get(), bytes.data() + offset,
                   static_cast<DWORD>(bytes.size() - offset), &written, nullptr) || !written) IoFailure();
    offset += written;
  }
  if (!FlushFileBuffers(handle_.get())) IoFailure();
}

void File::close() {
  std::lock_guard lock(mutex_);
  handle_.close();
  directory_.handles.clear();
}

}  // namespace openrdx::logs
