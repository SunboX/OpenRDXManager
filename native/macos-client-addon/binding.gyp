# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later

{
  "variables": {"openrdx_macos_team_id%": ""},
  "targets": [{
    "target_name": "openrdx_macos_client",
    "sources": ["openrdx_macos_client.cc", "../rdx-service/native/macos/rdx_endpoint_identity.c"],
    "defines": ["OPENRDX_MACOS_TEAM_ID=\"<(openrdx_macos_team_id)\""],
    "include_dirs": ["../rdx-service/native/macos"],
    "libraries": ["<(module_root_dir)/build/trust/release/libopenrdx_macos_client_trust.a", "-framework CoreFoundation", "-framework Security", "-lbsm"],
    "xcode_settings": {
      "CLANG_CXX_LANGUAGE_STANDARD": "c++20",
      "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
      "OTHER_CFLAGS": ["-Wall", "-Wextra", "-Werror", "-fstack-protector-strong"]
    }
  }]
}
