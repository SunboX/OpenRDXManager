// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "windows_log_files.h"
#include <winternl.h>
#include <cstddef>
#include <cstring>

namespace openrdx::logs {

/** Publishes a fixed sibling name through the retained source file's parent. */
void RenamePinnedFile(HANDLE file, const Directory& directory, RenameDestination target, bool replace) {
  if (directory.handles.empty() || (replace && target != RenameDestination::McpSettings))
    throw Failure{"windows-private-rename-invalid"};
  const std::wstring name = target == RenameDestination::LogBackup ? L"_RDXManager.bak" : L"settings.json";
  const size_t name_bytes = name.size() * sizeof(wchar_t);
  const size_t size = offsetof(FILE_RENAME_INFO, FileName) + name_bytes + sizeof(wchar_t);
  std::vector<std::uint64_t> storage((size + 7) / 8);
  auto* information = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
  // Ex semantics let the verified old settings handle remain open through the
  // atomic replacement. Never request readonly-attribute or access-check bypass.
  information->Flags = replace ? FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS : 0;
  information->RootDirectory = nullptr;
  information->FileNameLength = static_cast<DWORD>(name_bytes);
  std::memcpy(information->FileName, name.c_str(), name_bytes + sizeof(wchar_t));
  // A simple basename with null RootDirectory means the source file's existing
  // parent, not the process working directory. Supplying a destination directory
  // makes NT reopen it for write and conflicts with our retained no-write pins.
  // Keep those pins and use the documented same-directory rename instead.
  // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
  using SetInformation = NTSTATUS (NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
  const HMODULE module = GetModuleHandleW(L"ntdll.dll");
  const FARPROC address = module ? GetProcAddress(module, "NtSetInformationFile") : nullptr;
  SetInformation set_information = nullptr;
  static_assert(sizeof(set_information) == sizeof(address));
  std::memcpy(&set_information, &address, sizeof(address));
  if (!set_information) throw Failure{"windows-private-rename-unavailable"};
  IO_STATUS_BLOCK completion{};
  const NTSTATUS status = set_information(file, &completion, information,
      static_cast<ULONG>(size), static_cast<FILE_INFORMATION_CLASS>(65));
  if (status != 0 || completion.Status != 0) {
    switch (static_cast<ULONG>(status)) {
      case 0xC0000022: throw Failure{"windows-private-rename-access-denied"};
      case 0xC0000043: throw Failure{"windows-private-rename-sharing-violation"};
      case 0xC000000D: throw Failure{"windows-private-rename-invalid-parameter"};
      default: throw Failure{"windows-private-rename-failed"};
    }
  }
}
}  // namespace openrdx::logs
