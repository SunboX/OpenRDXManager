// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef OPENRDX_VERIFICATION_BUDGET_H
#define OPENRDX_VERIFICATION_BUDGET_H
#include <chrono>

namespace openrdx {
/** Time/cancellation checks only; callers own fresh successful cryptographic/byte policy proof. */
class VerificationBudget {
public:
    using Clock = std::chrono::steady_clock;
    /** Full protected byte/seal verification precedes the endpoint's independent seven seconds. */
    explicit VerificationBudget(Clock::time_point start) : policy_deadline_(start + std::chrono::seconds(45)) {}
    /** Caller MUST have completed fresh successful policy proof; never call after failed verification. */
    bool complete_policy(Clock::time_point now, bool cancelled) {
        if (peer_started_ || cancelled || now >= policy_deadline_) return false;
        peer_started_ = true;
        peer_deadline_ = now + std::chrono::seconds(7);
        return true;
    }
    /** Deadline remains constant throughout connect, pending-session wait and peer retries. */
    Clock::time_point peer_deadline() const { return peer_deadline_; }
    /** A late result or cancellation can never authorize a socket or publish ready. */
    bool peer_pending(Clock::time_point now, bool cancelled) const {
        return peer_started_ && !cancelled && now < peer_deadline_;
    }
private:
    Clock::time_point policy_deadline_;
    Clock::time_point peer_deadline_{};
    bool peer_started_ = false;
};
}
#endif
