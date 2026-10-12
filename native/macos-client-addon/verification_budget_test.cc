// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#include "verification_budget.h"
#include <cassert>
#include <chrono>
#include <cstdio>

/** Deterministic production budget boundaries, without devices, sockets or sleeps. */
int main() {
    using namespace std::chrono_literals;
    using Budget = openrdx::VerificationBudget;
    const auto start = Budget::Clock::time_point{};
    Budget measured(start);
    assert(!measured.peer_pending(start, false));
    assert(measured.complete_policy(start + 25107ms, false));
    assert(measured.peer_deadline() == start + 32107ms);
    assert(measured.peer_pending(start + 32106ms, false));
    assert(!measured.peer_pending(start + 32107ms, false));
    assert(!measured.complete_policy(start + 30000ms, false));
    assert(measured.peer_deadline() == start + 32107ms);
    Budget late(start);
    assert(!late.complete_policy(start + 45000ms, false));
    assert(!late.peer_pending(start + 45000ms, false));
    Budget cancelled(start);
    assert(!cancelled.complete_policy(start + 25107ms, true));
    assert(!cancelled.peer_pending(start + 25107ms, false));
    Budget boundary(start);
    assert(boundary.complete_policy(start + 44999ms, false));
    assert(boundary.peer_deadline() == start + 51999ms);
    assert(!boundary.peer_pending(start + 45000ms, true));
    std::puts("production verification budget: deterministic clock accepts CI 25.107s policy duration; policy45s and peer7s bounded; no retry reset or late/cancelled admission");
}
