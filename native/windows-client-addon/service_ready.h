// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string_view>

namespace openrdx {

/** Consumes only the fixed prelude; failures are sticky and never expose frames. */
class ServiceReadyPrelude {
 public:
  /** Returns exactly how many prelude bytes the next native read may request. */
  size_t remaining() const { return kMarker.size() - received_; }
  /** Reports readiness only after the complete versioned marker was accepted. */
  bool complete() const { return !failed_ && remaining() == 0; }
  /** Rejects EOF, excess bytes, mismatches and completion at/after the deadline. */
  bool consume(const char* bytes, size_t count, bool within_deadline) {
    if (failed_ || !within_deadline || count == 0 || count > remaining() ||
        std::memcmp(kMarker.data() + received_, bytes, count) != 0) {
      failed_ = true;
      return false;
    }
    received_ += count;
    return true;
  }

 private:
  static constexpr std::string_view kMarker = "OpenRDX:ready:1\n";
  size_t received_ = 0;
  bool failed_ = false;
};

}  // namespace openrdx
