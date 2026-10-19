// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>
#include "service_ready.h"

namespace openrdx::windows_io {

constexpr DWORD kMaxFrameStorage = 1'048'576;
constexpr DWORD kIoTimeoutMs = 2'000;
constexpr DWORD kCancelDrainTimeoutMs = 2'000;
constexpr DWORD kServiceReadyTimeoutMs = 45'000;
constexpr size_t kMaxPendingIoCount = 8;
constexpr size_t kMaxPendingIoBytes = 9 * 1024 * 1024;

struct ScopedHandle {
  HANDLE value = INVALID_HANDLE_VALUE;
  /** Closes only this operation-owned handle once. */
  ~ScopedHandle() {
    if (value != nullptr && value != INVALID_HANDLE_VALUE) CloseHandle(value);
  }
};

struct IoBudgetState {
  std::mutex mutex;
  size_t count = 0;
  size_t bytes = 0;
};

/** Retains aggregate accounting until process teardown, including unresolved I/O. */
inline IoBudgetState& PendingIoBudget() {
  // The budget deliberately has process lifetime. Unresolved kernel I/O also
  // retains its reservation until process teardown, so addon unload never
  // leaves an operation referring to destructed accounting storage.
  static IoBudgetState* budget = new IoBudgetState();
  return *budget;
}

/** Reserves bounded operation storage before kernel admission; false leaves it unchanged. */
inline bool TryReservePendingIoBudget(size_t reservation_bytes) {
  IoBudgetState& budget = PendingIoBudget();
  std::lock_guard<std::mutex> lock(budget.mutex);
  if (reservation_bytes == 0 || reservation_bytes > kMaxPendingIoBytes ||
      budget.count >= kMaxPendingIoCount ||
      budget.bytes > kMaxPendingIoBytes - reservation_bytes)
    return false;
  ++budget.count;
  budget.bytes += reservation_bytes;
  return true;
}

/** Releases a previously owned reservation after terminal proof or before admission. */
inline void ReleasePendingIoBudget(size_t reservation_bytes) {
  IoBudgetState& budget = PendingIoBudget();
  std::lock_guard<std::mutex> lock(budget.mutex);
  --budget.count;
  budget.bytes -= reservation_bytes;
}

class IoReservation {
 public:
  /** Adopts exactly one previously reserved storage budget. */
  explicit IoReservation(size_t bytes) : bytes_(bytes) {}
  IoReservation(const IoReservation&) = delete;
  IoReservation& operator=(const IoReservation&) = delete;
  /** Transfers ownership without changing aggregate accounting. */
  IoReservation(IoReservation&& other) noexcept
      : bytes_(std::exchange(other.bytes_, 0)) {}
  IoReservation& operator=(IoReservation&&) = delete;
  /** Returns the aggregate reservation exactly once. */
  ~IoReservation() {
    if (bytes_ != 0) ReleasePendingIoBudget(bytes_);
  }

 private:
  size_t bytes_;
};

struct PendingIo {
  IoReservation reservation;
  ScopedHandle pipe;
  ScopedHandle event;
  OVERLAPPED overlapped{};
  std::vector<std::uint8_t> storage;

  /** Retains handle, event, OVERLAPPED and storage for one bounded native operation. */
  PendingIo(size_t storage_size, IoReservation owned_reservation)
      : reservation(std::move(owned_reservation)), storage(storage_size) {
    event.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    overlapped.hEvent = event.value;
  }
};

/** Creates one monotonic absolute deadline; callers must not reset it per fragment. */
inline ULONGLONG DeadlineAfter(DWORD timeout_ms) {
  return GetTickCount64() + static_cast<ULONGLONG>(timeout_ms);
}

/** Returns the bounded remaining wait, with expiry represented by zero. */
inline DWORD RemainingMilliseconds(ULONGLONG deadline, DWORD maximum) {
  const ULONGLONG now = GetTickCount64();
  if (now >= deadline) return 0;
  const ULONGLONG remaining = deadline - now;
  return static_cast<DWORD>(
      std::min<ULONGLONG>(remaining, static_cast<ULONGLONG>(maximum)));
}

/** Allocates operation-owned storage only after reserving the shared count/byte budget. */
inline bool CreatePendingIo(size_t storage_size,
                     std::unique_ptr<PendingIo>* operation) {
  if (storage_size > kMaxFrameStorage) return false;
  const size_t reservation_bytes = sizeof(PendingIo) + storage_size;
  if (!TryReservePendingIoBudget(reservation_bytes)) return false;
  IoReservation reservation(reservation_bytes);
  try {
    *operation =
        std::make_unique<PendingIo>(storage_size, std::move(reservation));
  } catch (...) {
    return false;
  }
  return true;
}

/** Gives one operation its own pipe handle so connection teardown cannot release it early. */
inline bool DuplicateIoHandle(HANDLE source, PendingIo* operation) {
  HANDLE duplicate = INVALID_HANDLE_VALUE;
  if (source == INVALID_HANDLE_VALUE || operation->event.value == nullptr ||
      !DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(),
                       &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return false;
  operation->pipe.value = duplicate;
  return true;
}

/** Retains unresolved kernel operation ownership and its budget until process exit. */
inline void PreservePendingIoForProcessLifetime(
    std::unique_ptr<PendingIo> operation) {
  // The aggregate count/byte reservation stays held with this unresolved
  // kernel operation. Deliberately abandon the bounded owning pointer so no
  // handle, OVERLAPPED, event, or storage is released before process teardown.
  (void)operation.release();
}

/** Distinguishes terminal success/failure from incomplete I/O without freeing its storage. */
inline bool ObservePendingIoTerminal(PendingIo* operation, DWORD* transferred,
                              bool* succeeded) {
  if (GetOverlappedResult(operation->pipe.value, &operation->overlapped,
                          transferred, FALSE)) {
    *succeeded = true;
    return true;
  }
  *succeeded = false;
  return GetLastError() != ERROR_IO_INCOMPLETE;
}

/** Cancels this exact operation and releases it only after bounded terminal proof. */
inline void CancelAndDrainPendingIo(std::unique_ptr<PendingIo>* owned_operation) {
  PendingIo* operation = owned_operation->get();
  if (!CancelIoEx(operation->pipe.value, &operation->overlapped)) {
    const DWORD cancel_error = GetLastError();
    // ERROR_NOT_FOUND means completion won the cancellation race. The event
    // and GetOverlappedResult below remain the authoritative terminal proof.
    if (cancel_error != ERROR_NOT_FOUND) {
      SetLastError(cancel_error);
    }
  }
  const DWORD wait =
      WaitForSingleObject(operation->event.value, kCancelDrainTimeoutMs);
  if (wait == WAIT_OBJECT_0) {
    DWORD transferred = 0;
    bool succeeded = false;
    if (ObservePendingIoTerminal(operation, &transferred, &succeeded)) return;
  }
  PreservePendingIoForProcessLifetime(std::move(*owned_operation));
}

/** Reads only readiness bytes within the caller's one absolute deadline.
 * Pending kernel I/O retains its exact storage and reservation until terminal
 * completion, including cancellation; uncertain drain uses the existing bound.
 */
inline bool ReadServiceReady(HANDLE pipe, HANDLE stop_event,
                             ULONGLONG readiness_deadline) {
  openrdx::ServiceReadyPrelude prelude;
  while (!prelude.complete()) {
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT ||
        RemainingMilliseconds(readiness_deadline, 1) == 0) return false;
    std::unique_ptr<PendingIo> operation;
    if (!CreatePendingIo(prelude.remaining(), &operation) ||
        !DuplicateIoHandle(pipe, operation.get())) return false;
    DWORD read = 0;
    const BOOL completed = ReadFile(operation->pipe.value,
        operation->storage.data(), static_cast<DWORD>(prelude.remaining()),
        &read, &operation->overlapped);
    if (!completed && GetLastError() == ERROR_IO_PENDING) {
      // STOP wins if both events are already signalled. All fragments retain
      // the caller's one deadline; no ready-specific timeout is restarted.
      HANDLE waits[] = {stop_event, operation->event.value};
      const DWORD wait = WaitForMultipleObjects(2, waits, FALSE,
          RemainingMilliseconds(readiness_deadline, MAXDWORD - 1));
      bool succeeded = false;
      const bool terminal = wait == WAIT_OBJECT_0 + 1 &&
          ObservePendingIoTerminal(operation.get(), &read, &succeeded);
      if (!terminal || !succeeded) {
        if (!terminal) CancelAndDrainPendingIo(&operation);
        return false;
      }
    } else if (!completed) {
      return false;
    }
    // Synchronous completion can also cross the deadline or race destroy.
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT ||
        !prelude.consume(reinterpret_cast<const char*>(operation->storage.data()),
            read, RemainingMilliseconds(readiness_deadline, 1) != 0))
      return false;
  }
  return true;
}

/** Waits after peer proof for the service's fresh runtime verification/backend
 * preparation, retaining one absolute marker deadline and existing cancellation.
 */
inline bool ReadServiceReadyAfterProof(HANDLE pipe, HANDLE stop_event) {
  return ReadServiceReady(pipe, stop_event, DeadlineAfter(kServiceReadyTimeoutMs));
}

}  // namespace openrdx::windows_io
