// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifdef NDEBUG
#undef NDEBUG
#endif
#include "service_ready.h"
#ifdef _WIN32
#include "windows_pipe_io.h"
#include <thread>
#include <atomic>
#include <string>
#endif
#include <cassert>
#include <cstdio>
#include <string_view>

#ifdef _WIN32
/** Runs real private-pipe I/O only; never names the installed service or dock. */
void CheckPrivatePipe(std::string bytes, DWORD pause_ms, bool partial,
                      DWORD deadline_ms, DWORD cancel_ms, bool expected,
                      bool race = false) {
  using namespace openrdx::windows_io;
  static unsigned sequence = 0;
  const std::wstring name = L"\\\\.\\pipe\\OpenRDXReadyTest-" +
      std::to_wstring(GetCurrentProcessId()) + L"-" +
      std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++sequence);
  ScopedHandle server;
  server.value = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX |
      FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
      PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 512, 512, 1000, nullptr);
  assert(server.value != INVALID_HANDLE_VALUE);
  std::atomic<bool> finished{false};
  std::thread producer([&] {
    const bool connected = ConnectNamedPipe(server.value, nullptr) != FALSE ||
                           GetLastError() == ERROR_PIPE_CONNECTED;
    assert(connected);
    const size_t prefix = partial ? 7 : 0;
    DWORD written = 0;
    if (prefix != 0) WriteFile(server.value, bytes.data(),
        static_cast<DWORD>(prefix), &written, nullptr);
    Sleep(pause_ms);
    if (bytes.size() > prefix) WriteFile(server.value, bytes.data() + prefix,
        static_cast<DWORD>(bytes.size() - prefix), &written, nullptr);
    if (bytes.size() >= 16) {
      const ULONGLONG deadline = DeadlineAfter(2000);
      while (!finished.load() && RemainingMilliseconds(deadline, 1) != 0) Sleep(1);
    }
    DisconnectNamedPipe(server.value);
  });
  ScopedHandle client;
  client.value = CreateFileW(name.c_str(), FILE_READ_DATA | FILE_WRITE_DATA |
      SYNCHRONIZE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED |
      SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
  assert(client.value != INVALID_HANDLE_VALUE);
  ScopedHandle stop;
  stop.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  assert(stop.value != nullptr);
  std::thread canceller;
  if (cancel_ms != INFINITE) canceller = std::thread([&] {
    Sleep(cancel_ms); SetEvent(stop.value);
  });
  const bool ready = ReadServiceReady(client.value, stop.value,
                                      DeadlineAfter(deadline_ms));
  if (!race) assert(ready == expected);
  if (ready && bytes.size() == 21) {
    DWORD available = 0;
    assert(PeekNamedPipe(client.value, nullptr, 0, nullptr, &available, nullptr));
    assert(available == 5);
  }
  finished.store(true);
  if (canceller.joinable()) canceller.join();
  producer.join();
  auto& budget = PendingIoBudget();
  std::lock_guard<std::mutex> lock(budget.mutex);
  assert(budget.count == 0 && budget.bytes == 0);
}

/** Verifies native completion/cancellation and fixed deadlines on real Windows. */
void CheckWindowsPipeControls() {
  CheckPrivatePipe("OpenRDX:ready:1\n", 0, false, 1000, INFINITE, true);
  CheckPrivatePipe("OpenRDX:ready:1\nFRAME", 0, false, 1000, INFINITE, true);
  CheckPrivatePipe("OpenRDX:ready:1\n", 0, false, 0, INFINITE, false);
  CheckPrivatePipe("OpenRDX:ready:1\n", 5, true, 1000, INFINITE, true);
  CheckPrivatePipe("OpenRDX:ready:2\n", 0, false, 1000, INFINITE, false);
  CheckPrivatePipe("OpenRDX", 0, false, 1000, INFINITE, false);
  CheckPrivatePipe("", 100, false, 20, INFINITE, false);
  CheckPrivatePipe("OpenRDX:ready:1\n", 100, true, 20, INFINITE, false);
  CheckPrivatePipe("OpenRDX:ready:1\n", 100, false, 1000, 10, false);
  for (unsigned i = 0; i != 8; ++i)
    CheckPrivatePipe("OpenRDX:ready:1\n", 10, false, 1000, 10, false, true);
  std::puts("service-ready Windows private pipes: complete, partial, malformed, EOF, idle, cancellation race and resource retirement PASS");
}
#endif

/** Exercises the real fixed prelude parser with independently specified bytes. */
int main() {
  using openrdx::ServiceReadyPrelude;
  constexpr std::string_view marker = "OpenRDX:ready:1\n";
  for (size_t chunk : {size_t{1}, size_t{3}, size_t{16}}) {
    ServiceReadyPrelude parser;
    for (size_t offset = 0; offset < marker.size();) {
      const size_t count = std::min(chunk, marker.size() - offset);
      assert(parser.consume(marker.data() + offset, count, true));
      offset += count;
      assert(parser.complete() == (offset == marker.size()));
      assert(parser.remaining() == marker.size() - offset);
    }
  }
  for (std::string_view bad : {"OpenRDX:ready:2\n", "OpenRDX:ready:1!", "BAD"}) {
    ServiceReadyPrelude parser;
    assert(!parser.consume(bad.data(), bad.size(), true));
    assert(!parser.complete());
    assert(!parser.consume(marker.data(), marker.size(), true));
  }
  for (size_t prefix : {size_t{0}, size_t{7}, size_t{15}}) {
    ServiceReadyPrelude parser;
    if (prefix != 0) assert(parser.consume(marker.data(), prefix, true));
    assert(!parser.complete());
    assert(!parser.consume(marker.data() + prefix, marker.size() - prefix, false));
    assert(!parser.complete());
  }
  ServiceReadyPrelude eof;
  assert(!eof.consume(marker.data(), 0, true));
  ServiceReadyPrelude overread;
  assert(!overread.consume("OpenRDX:ready:1\nFRAME", 21, true));
  assert(!overread.complete());
#ifdef _WIN32
  CheckWindowsPipeControls();
#endif
  std::puts("service-ready parser: fragmentation, exact version, EOF, overflow and absolute deadline PASS");
}
