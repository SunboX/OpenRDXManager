// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

#include <node_api.h>
#include <windows.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace openrdx::logs {

constexpr size_t kMaximumRead = 16 * 1024 * 1024 + 16'384 + 1;

/** Path-free failure propagated to the asynchronous JavaScript boundary. */
struct Failure {
  const char* code;
};

/** Move-only ownership of one non-inherited Windows kernel handle. */
class Handle {
 public:
  /** Adopts a handle or creates an empty owner. */
  explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept;
  /** Closes the owned handle once. */
  ~Handle();
  /** Transfers ownership without duplicating the kernel resource. */
  Handle(Handle&& other) noexcept;
  /** Replaces this owner by consuming another owner. */
  Handle& operator=(Handle&& other) noexcept;
  /** Kernel handles cannot be copied. */
  Handle(const Handle&) = delete;
  /** Kernel handles cannot be copy-assigned. */
  Handle& operator=(const Handle&) = delete;
  /** Returns the still-owned native handle to this private boundary. */
  HANDLE get() const noexcept;
  /** Closes and clears the handle; repeated close is harmless. */
  void close() noexcept;
 private:
  HANDLE value_;
};

/** Pins all ancestors against rename/reparse replacement during file access. */
struct Directory {
  std::wstring path;
  std::vector<Handle> handles;
};

/** Closed names that can be published beneath an already-pinned directory. */
enum class RenameDestination { LogBackup, McpSettings };
/** Renames by retained directory authority; replacement is limited to MCP settings. */
void RenamePinnedFile(HANDLE file, const Directory& directory, RenameDestination target, bool replace);

class Root;
class McpStore;

/** An exact verified file, including retained ancestor handles. */
class File {
 public:
  /** Retains the exact root, ancestors, file and narrow access purpose. */
  File(std::shared_ptr<Root> root, Directory directory, Handle handle, bool append);
  /** Reads verified regular-file size without exposing a native handle. */
  std::uint64_t size();
  /** Reads a bounded range through the same retained read-only handle. */
  std::vector<std::uint8_t> read(size_t length, size_t position);
  /** Appends and flushes bytes durably through the retained write handle. */
  void append(const std::vector<std::uint8_t>& bytes);
  /** Releases the file before its pinned ancestors, once. */
  void close();
 private:
  std::shared_ptr<Root> root_;
  Directory directory_;
  Handle handle_;
  bool append_;
  std::mutex mutex_;
};

/** Authority for exactly the two logger filenames under a main-owned directory. */
class Root : public std::enable_shared_from_this<Root> {
  friend class McpStore;
 public:
  /** Validates local path syntax and captures the process user SID, without file I/O. */
  explicit Root(std::wstring path);
  /** Frees the private creation security descriptor. */
  ~Root();
  /** Rejects accidental copying of security descriptor ownership. */
  Root(const Root&) = delete;
  /** Rejects accidental copy assignment. */
  Root& operator=(const Root&) = delete;
  /** Creates missing directories and verifies/hardens only the exact final directory. */
  void prepare();
  /** Opens one fixed current/backup log and retains its exact ancestry. */
  std::shared_ptr<File> open(bool backup, bool append);
  /** Deletes only a verified backup by handle, or confirms its absence. */
  void remove_backup();
  /** Renames the verified current file to an absent backup without replacement. */
  void rotate();
  /** Verifies type, owner, single link and user-only DACL; optionally tightens DACL. */
  BY_HANDLE_FILE_INFORMATION verify(HANDLE handle, bool directory, bool harden) const;
 private:
  /** Resolves and pins each component using a stable volume-GUID namespace. */
  Directory pin(bool create);
  /** Opens one fixed file name with no-follow semantics and exact DACL proof. */
  Handle open_file(const Directory& directory, bool backup, DWORD access, bool create);
  std::wstring drive_;
  std::vector<std::wstring> components_;
  std::vector<std::uint8_t> sid_;
  PSECURITY_DESCRIPTOR security_ = nullptr;
};

/** Registers the asynchronous private-log factory alongside the named-pipe client. */
napi_status RegisterLogFiles(napi_env env, napi_value exports);

}  // namespace openrdx::logs
