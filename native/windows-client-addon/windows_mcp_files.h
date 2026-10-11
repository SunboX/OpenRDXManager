// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once
#include "windows_log_files.h"

namespace openrdx::logs {

/** Private MCP settings/token authority; callers cannot choose filenames. */
class McpStore {
 public:
  /** Captures an exact main-owned directory and current Windows user. */
  explicit McpStore(std::wstring path);
  /** Prepares only the selected owned directory, without reading credentials. */
  void prepare();
  /** Reads one bounded fixed file after native no-follow, owner and DACL proof. */
  std::vector<std::uint8_t> read(bool token);
  /** Publishes complete settings atomically; never writes through an existing file. */
  void write_settings(const std::vector<std::uint8_t>& bytes);
  /** Creates the fixed token exclusively or validates and returns the existing token. */
  std::vector<std::uint8_t> ensure_token(const std::vector<std::uint8_t>& proposed);
 private:
  /** Opens a fixed file under retained ancestors and rejects unsafe existing objects. */
  Handle open(const Directory& directory, bool token, DWORD access, DWORD sharing);
  /** Reads and bounds bytes using the same already-verified retained handle. */
  std::vector<std::uint8_t> read_handle(HANDLE handle, size_t maximum);
  /** Reads a token/settings file while the store's serialization lock is held. */
  std::vector<std::uint8_t> read_locked(bool token);
  std::shared_ptr<Root> root_;
  std::mutex mutex_;
};

}  // namespace openrdx::logs
