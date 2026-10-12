// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#include <node_api.h>
#include "rdx_endpoint_identity.h"
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

extern "C" bool rdx_macos_client_verified_hashes(unsigned char*, unsigned char*, size_t);
extern "C" bool rdx_macos_client_verify_signed_runtime();
extern "C" uint32_t rdx_macos_client_last_trust_stage();
namespace {
constexpr char kEndpoint[] = "/var/run/openrdx-hardware.sock";
constexpr char kHelper[] = "/Library/PrivilegedHelperTools/openrdx-hardware";
constexpr char kSignedHelper[] = "/Applications/OpenRDXManager.app/Contents/Library/LaunchServices/openrdx-hardware";
constexpr size_t kMaxFrame = 1'048'576;
constexpr size_t kMaxConnections = 8;
std::atomic<size_t> live_connections{0};
using Clock = std::chrono::steady_clock;

/** Native events own bounded storage until delivered or discarded by Node. */
struct Event { std::string type; std::string reason; std::vector<unsigned char> data; std::shared_ptr<std::atomic<size_t>> pending; };
/** Retains the exact authenticated socket, cancellation guard and Node callback. */
struct Connection {
    std::mutex mutex;
    int fd = -1;
    bool verified = false;
    const char* proof_stage = "not-started";
    size_t proof_attempts = 0;
    int64_t policy_ms = 0;
    int64_t peer_ms = 0;
    std::atomic<bool> cancelled{false};
    std::atomic<bool> slot_released{false};
    std::shared_ptr<std::atomic<size_t>> pending = std::make_shared<std::atomic<size_t>>(0);
    napi_threadsafe_function callback = nullptr;
    ~Connection() { if (fd >= 0) close(fd); if (!slot_released.exchange(true)) live_connections.fetch_sub(1); }
};
std::mutex registry_mutex;
std::vector<std::weak_ptr<Connection>> connections;

/** Retain a stable snapshot without holding registry locks during code checks. */
std::vector<std::shared_ptr<Connection>> SnapshotConnections() {
    std::vector<std::shared_ptr<Connection>> snapshot;
    std::lock_guard<std::mutex> lock(registry_mutex);
    for (const auto& weak : connections) { if (auto connection = weak.lock()) snapshot.push_back(connection); }
    return snapshot;
}
/** Remove a terminal socket from the bounded active registry. */
void RemoveConnection(Connection* ended) {
    std::lock_guard<std::mutex> lock(registry_mutex);
    std::erase_if(connections, [ended](const std::weak_ptr<Connection>& weak) {
        const auto retained = weak.lock(); return !retained || retained.get() == ended;
    });
}
/** Worker storage retains connection ownership until the Node completion callback. */
struct Work { std::shared_ptr<Connection> connection; napi_async_work work = nullptr; bool cleanup_registered = false; };

/** Deliver only the fixed event vocabulary; release event storage on all paths. */
void Deliver(napi_env env, napi_value callback, void*, void* raw) {
    std::unique_ptr<Event> event(static_cast<Event*>(raw));
    if (event->pending) event->pending->fetch_sub(1);
    if (!env || !callback) return;
    napi_value object, value, ignored;
    if (napi_create_object(env, &object) != napi_ok) return;
    napi_create_string_utf8(env, event->type.c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, object, "type", value);
    if (!event->reason.empty()) {
        napi_create_string_utf8(env, event->reason.c_str(), NAPI_AUTO_LENGTH, &value);
        napi_set_named_property(env, object, "reason", value);
    }
    if (!event->data.empty()) {
        napi_create_buffer_copy(env, event->data.size(), event->data.data(), nullptr, &value);
        napi_set_named_property(env, object, "data", value);
    }
    napi_get_undefined(env, &value);
    napi_call_function(env, value, callback, 1, &object, &ignored);
}
/** Push with bounded native/JS aggregate buffering; queue exhaustion cancels IO. */
bool Emit(Connection& connection, Event event) {
    if (event.type == "data") {
        if (connection.pending->fetch_add(1) >= 16) {
            connection.pending->fetch_sub(1); connection.cancelled.store(true); return false;
        }
        event.pending = connection.pending;
    }
    auto owned = std::make_unique<Event>(std::move(event));
    if (napi_call_threadsafe_function(connection.callback, owned.get(), napi_tsfn_nonblocking) != napi_ok) {
        if (owned->pending) owned->pending->fetch_sub(1);
        connection.cancelled.store(true); return false;
    }
    owned.release(); return true;
}
/** Cancel without joining a worker or recycling its still-retained descriptor. */
void Cancel(Connection& connection) {
    connection.cancelled.store(true);
    std::lock_guard<std::mutex> lock(connection.mutex);
    connection.verified = false;
    if (connection.fd >= 0) shutdown(connection.fd, SHUT_RDWR);
}
/** Poll the retained descriptor in short cancellation-aware bounded slices. */
bool Wait(Connection& connection, short events, Clock::time_point deadline) {
    while (!connection.cancelled.load() && Clock::now() < deadline) {
        pollfd descriptor{connection.fd, events, 0};
        int ready = poll(&descriptor, 1, 20);
        if (ready > 0) return (descriptor.revents & events) != 0;
        if (ready < 0 && errno != EINTR) return false;
    }
    return false;
}
/** One selected mode's immutable helper policy; never caller-authored input. */
struct PeerPolicy { std::string requirement; const char* helper = nullptr; };
/** Select sealed mode once, with no fallback after any enrollment/code failure. */
bool VerifyInstalledPolicy(PeerPolicy& policy, bool local_only = false) {
    return rdx_macos_verify_selected_mode(rdx_macos_current_installation_mode(), local_only,
        [](void* raw) -> bool {
            auto& selected = *static_cast<PeerPolicy*>(raw);
            unsigned char helper_hash[41]{}, manager_hash[41]{};
            if (!rdx_macos_client_verified_hashes(helper_hash, manager_hash, sizeof(helper_hash))) return false;
            const std::string manager_requirement = "identifier \"com.openrdx.manager\" and cdhash H\"" + std::string(reinterpret_cast<char*>(manager_hash)) + "\"";
            if (!rdx_macos_current_manager_matches(manager_requirement.c_str()) ||
                rdx_macos_current_installation_mode() != RDX_INSTALLATION_LOCAL) return false;
            selected.requirement = "identifier \"com.openrdx.hardware\" and cdhash H\"" + std::string(reinterpret_cast<char*>(helper_hash)) + "\"";
            selected.helper = kHelper;
            return true;
        },
        [](void* raw) -> bool {
            auto& selected = *static_cast<PeerPolicy*>(raw);
            char requirement[256];
            if (!rdx_macos_signed_helper_requirement(requirement, sizeof(requirement)) ||
                !rdx_macos_client_verify_signed_runtime() ||
                rdx_macos_current_installation_mode() != RDX_INSTALLATION_SIGNED) return false;
            selected.requirement = requirement;
            selected.helper = kSignedHelper;
            return true;
        }, &policy);
}
/** Open only the fixed root-protected Unix socket before auditing its peer. */
const char* OpenAndVerify(Connection& connection, Clock::time_point deadline, bool local_only = false) {
    const auto started = Clock::now();
    connection.proof_stage = "manager-location";
    if (!rdx_macos_current_process_is_installed_manager()) return "service-identity-unverified";
    connection.proof_stage = "installation-policy";
    PeerPolicy policy;
    if (!VerifyInstalledPolicy(policy, local_only)) return "service-identity-unverified";
    connection.policy_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count();
    connection.proof_stage = "endpoint-protection";
    if (!rdx_macos_endpoint_path_is_protected()) return "service-not-installed";
    if (connection.cancelled.load() || Clock::now() >= deadline) return "service-exited";
    connection.proof_stage = "endpoint-open";
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return "service-exited";
    {
        std::lock_guard<std::mutex> lock(connection.mutex);
        connection.fd = fd;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fcntl(fd, F_SETFL, O_NONBLOCK) != 0) return "service-exited";
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) return "service-exited";
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::strcpy(address.sun_path, kEndpoint);
    connection.proof_stage = "endpoint-connect";
    if (connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        if (errno != EINPROGRESS) return errno == EACCES ? "insufficient-permission" : "service-not-installed";
        if (!Wait(connection, POLLOUT, deadline)) return "service-exited";
        int error = 0; socklen_t length = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0) return "service-exited";
    }
    // launchd creates the listener. Wait for accept() to attach the helper's
    // audit token; never send an application handshake to solicit that identity.
    const auto peer_started = Clock::now();
    connection.proof_stage = "peer-proof";
    while (!connection.cancelled.load() && Clock::now() < deadline) {
        connection.proof_attempts += 1;
        uint32_t uid = 0;
        if (rdx_macos_peer_identity_matches(fd, policy.requirement.c_str(), policy.helper, 0, &uid)) {
            std::lock_guard<std::mutex> lock(connection.mutex);
            if (connection.cancelled.load() || Clock::now() >= deadline) return "service-exited";
            connection.peer_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - peer_started).count();
            connection.verified = true;
            return nullptr;
        }
        pollfd descriptor{fd, 0, 0};
        if (poll(&descriptor, 1, 20) < 0 && errno != EINTR) break;
        if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
    }
    connection.peer_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - peer_started).count();
    return "service-identity-unverified";
}
/** Cancel retained native IO when the Node environment is closing. */
void Cleanup(void* raw) {
    auto& work = *static_cast<Work*>(raw);
    work.cleanup_registered = false;
    Cancel(*work.connection);
}
/** Authenticate before connect/data events and retain socket through the read loop. */
void Execute(napi_env, void* raw) {
    auto& connection = *static_cast<Work*>(raw)->connection;
    const char* failure = OpenAndVerify(connection, Clock::now() + std::chrono::seconds(7));
    if (failure) {
        const auto detail = rdx_macos_last_identity_diagnostic();
        // One bounded terminal record per attempt. Fixed phase strings/numeric
        // codes only; no raw paths, code hashes, protocol bytes or inventory.
        std::fprintf(stderr, "OpenRDXManager native identity failure: phase=%s identity=%s code=%d peer-pid=%d peer-uid=%u trust-phase=%u attempts=%zu policy-ms=%lld peer-ms=%lld\n",
            connection.proof_stage, detail.stage, detail.code, detail.peer_pid, detail.peer_uid,
            rdx_macos_client_last_trust_stage(), connection.proof_attempts, static_cast<long long>(connection.policy_ms), static_cast<long long>(connection.peer_ms));
        Emit(connection, {"error", failure, {}, {}});
    }
    else if (Emit(connection, {"connect", {}, {}, {}})) {
        std::fprintf(stderr, "OpenRDXManager native identity verified: policy-ms=%lld peer-ms=%lld attempts=%zu\n",
            static_cast<long long>(connection.policy_ms), static_cast<long long>(connection.peer_ms), connection.proof_attempts);
        while (!connection.cancelled.load()) {
            if (!Wait(connection, POLLIN, Clock::now() + std::chrono::milliseconds(100))) {
                pollfd descriptor{connection.fd, 0, 0};
                if (poll(&descriptor, 1, 0) >= 0 && (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) break;
                continue;
            }
            std::vector<unsigned char> bytes(65'536);
            ssize_t count = recv(connection.fd, bytes.data(), bytes.size(), 0);
            if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (count <= 0) break;
            bytes.resize(static_cast<size_t>(count));
            if (!Emit(connection, {"data", {}, std::move(bytes), {}})) break;
        }
    }
    Cancel(connection);
    {
        std::lock_guard<std::mutex> lock(connection.mutex);
        if (connection.fd >= 0) { close(connection.fd); connection.fd = -1; }
    }
    RemoveConnection(&connection);
    if (!connection.slot_released.exchange(true)) live_connections.fetch_sub(1);
    // Sixteen bounded data slots plus connect leave a terminal slot available;
    // native close delivery never waits on the JavaScript event loop.
    Emit(connection, {"close", {}, {}, {}});
    napi_release_threadsafe_function(connection.callback, napi_tsfn_release);
}
/** Reclaim bounded worker storage when Node observes native completion. */
void Complete(napi_env env, napi_status, void* raw) {
    std::unique_ptr<Work> work(static_cast<Work*>(raw));
    if (work->cleanup_registered) napi_remove_env_cleanup_hook(env, Cleanup, work.get());
    napi_delete_async_work(env, work->work);
}
/** Retrieve the opaque native ownership wrapper without exposing its fd. */
std::shared_ptr<Connection>* Unwrap(napi_env env, napi_callback_info info, size_t* argc, napi_value* argv) {
    napi_value self; void* raw = nullptr;
    if (napi_get_cb_info(env, info, argc, argv, &self, nullptr) != napi_ok || napi_unwrap(env, self, &raw) != napi_ok) return nullptr;
    return static_cast<std::shared_ptr<Connection>*>(raw);
}
/** Cancel a connection during GC; the worker retains independent ownership. */
void Finalize(napi_env, void* raw, void*) {
    std::unique_ptr<std::shared_ptr<Connection>> owned(static_cast<std::shared_ptr<Connection>*>(raw));
    Cancel(**owned);
}
/** Idempotently request native cancellation; close is emitted only by the worker. */
napi_value Destroy(napi_env env, napi_callback_info info) {
    size_t argc = 0; auto* owned = Unwrap(env, info, &argc, nullptr);
    if (owned) Cancel(**owned);
    napi_value result; napi_get_undefined(env, &result); return result;
}
/** Write bounded protocol bytes only on the already authenticated retained fd. */
napi_value Write(napi_env env, napi_callback_info info) {
    napi_value argument; size_t argc = 1;
    auto* owned = Unwrap(env, info, &argc, &argument);
    bool accepted = false, buffer = false; void* data = nullptr; size_t length = 0;
    if (owned && argc == 1 && napi_is_buffer(env, argument, &buffer) == napi_ok && buffer &&
        napi_get_buffer_info(env, argument, &data, &length) == napi_ok && length > 0 && length <= kMaxFrame) {
        auto& connection = **owned;
        std::lock_guard<std::mutex> lock(connection.mutex);
        if (connection.verified && !connection.cancelled.load() && connection.fd >= 0) {
            size_t offset = 0;
            const auto deadline = Clock::now() + std::chrono::milliseconds(100);
            while (offset < length && !connection.cancelled.load() && Clock::now() < deadline) {
                ssize_t count = send(connection.fd, static_cast<unsigned char*>(data) + offset, length - offset, 0);
                if (count > 0) offset += static_cast<size_t>(count);
                else if (count < 0 && errno == EINTR) continue;
                else if (count < 0 && errno == EAGAIN && Wait(connection, POLLOUT, deadline)) continue;
                else break;
            }
            accepted = offset == length;
            if (!accepted) { connection.verified = false; connection.cancelled.store(true); shutdown(connection.fd, SHUT_RDWR); }
        }
    }
    napi_value result; napi_get_boolean(env, accepted, &result); return result;
}
/** Create a callback-only fixed-policy connection; reject all path/hash input. */
napi_value Connect(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value arguments[2], result, name; napi_valuetype type;
    napi_get_cb_info(env, info, &argc, arguments, nullptr, nullptr);
    if (argc != 1 || napi_typeof(env, arguments[0], &type) != napi_ok || type != napi_function) {
        napi_throw_type_error(env, nullptr, "macos-client-callback-invalid"); return nullptr;
    }
    size_t count = live_connections.fetch_add(1);
    if (count >= kMaxConnections) {
        live_connections.fetch_sub(1); napi_throw_error(env, nullptr, "macos-client-resource-limit"); return nullptr;
    }
    auto connection = std::make_shared<Connection>();
    napi_create_string_utf8(env, "openrdx-macos-client", NAPI_AUTO_LENGTH, &name);
    if (napi_create_threadsafe_function(env, arguments[0], nullptr, name, 18, 1, nullptr, nullptr, nullptr, Deliver, &connection->callback) != napi_ok) {
        napi_throw_error(env, nullptr, "macos-client-native-failure"); return nullptr;
    }
    napi_create_object(env, &result);
    auto owned = std::make_unique<std::shared_ptr<Connection>>(connection);
    napi_wrap(env, result, owned.get(), Finalize, nullptr, nullptr); owned.release();
    const napi_property_descriptor properties[] = {
        {"write", nullptr, Write, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"destroy", nullptr, Destroy, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"end", nullptr, Destroy, nullptr, nullptr, nullptr, napi_default, nullptr}
    };
    napi_define_properties(env, result, 3, properties);
    auto work = std::make_unique<Work>(); work->connection = connection;
    if (napi_create_async_work(env, nullptr, name, Execute, Complete, work.get(), &work->work) != napi_ok || napi_queue_async_work(env, work->work) != napi_ok) {
        if (work->work) napi_delete_async_work(env, work->work);
        napi_release_threadsafe_function(connection->callback, napi_tsfn_abort);
        napi_throw_error(env, nullptr, "macos-client-native-failure"); return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(registry_mutex);
        connections.push_back(connection);
    }
    if (napi_add_env_cleanup_hook(env, Cleanup, work.get()) == napi_ok) work->cleanup_registered = true;
    work.release(); return result;
}
/** Promise-owned no-device status verification operation. */
struct StatusWork { napi_async_work work = nullptr; napi_deferred deferred = nullptr; std::string status; bool consumed = false; };
/** Verify current process and installed endpoint without sending protocol bytes. */
void StatusExecute(napi_env, void* raw) {
    auto& task = *static_cast<StatusWork*>(raw);
    if (!rdx_macos_current_process_is_installed_manager()) { task.status = "installer-required"; return; }
    if (access("/Library/Application Support/OpenRDXManager/LocalTrust/runtime.json", F_OK) != 0 && errno == ENOENT) {
        task.status = "installer-required"; return;
    }
    const auto deadline = Clock::now() + std::chrono::seconds(7);
    PeerPolicy policy;
    if (!VerifyInstalledPolicy(policy, true)) { task.status = "repair-required"; return; }
    // The service deliberately serializes sessions. Re-prove its current
    // retained connection instead of queueing another accept behind it.
    while (Clock::now() < deadline) {
        bool pending = false;
        for (const auto& retained : SnapshotConnections()) {
            std::lock_guard<std::mutex> lock(retained->mutex);
            if (retained->cancelled.load()) continue;
            if (!retained->verified) { pending = true; continue; }
            uint32_t uid = 0;
            task.status = retained->fd >= 0 && rdx_macos_endpoint_path_is_protected() &&
                rdx_macos_peer_identity_matches(retained->fd, policy.requirement.c_str(), policy.helper, 0, &uid) ? "enabled" : "repair-required";
            return;
        }
        if (!pending) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (Clock::now() >= deadline) { task.status = "repair-required"; return; }
    Connection connection;
    task.consumed = true;
    const char* failure = OpenAndVerify(connection, deadline, true);
    task.status = failure == nullptr ? "enabled" : "repair-required";
    Cancel(connection);
}
/** Resolve only the closed status enum after releasing the retained proof socket. */
void StatusComplete(napi_env env, napi_status status, void* raw) {
    std::unique_ptr<StatusWork> task(static_cast<StatusWork*>(raw));
    napi_value value;
    const char* result = status == napi_ok ? task->status.c_str() : "repair-required";
    napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &value);
    napi_resolve_deferred(env, task->deferred, value);
    napi_delete_async_work(env, task->work);
    if (!task->consumed) live_connections.fetch_sub(1);
}
/** Fixed zero-argument asynchronous native installation status, never trust enrollment. */
napi_value LocalTrustStatus(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argument, promise, name;
    napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr);
    if (argc != 0) { napi_throw_type_error(env, nullptr, "macos-client-status-arguments-invalid"); return nullptr; }
    if (live_connections.fetch_add(1) >= kMaxConnections) {
        live_connections.fetch_sub(1); napi_throw_error(env, nullptr, "macos-client-resource-limit"); return nullptr;
    }
    auto task = std::make_unique<StatusWork>();
    napi_create_promise(env, &task->deferred, &promise);
    napi_create_string_utf8(env, "openrdx-local-trust-status", NAPI_AUTO_LENGTH, &name);
    if (napi_create_async_work(env, nullptr, name, StatusExecute, StatusComplete, task.get(), &task->work) != napi_ok ||
        napi_queue_async_work(env, task->work) != napi_ok) {
        if (task->work) napi_delete_async_work(env, task->work);
        napi_value value; napi_create_string_utf8(env, "repair-required", NAPI_AUTO_LENGTH, &value);
        napi_resolve_deferred(env, task->deferred, value); live_connections.fetch_sub(1); return promise;
    }
    task.release(); return promise;
}
/** Export only the fixed native connector, no raw handles or trust-policy setters. */
napi_value Initialize(napi_env env, napi_value exports) {
    const napi_property_descriptor property = {"connect", nullptr, Connect, nullptr, nullptr, nullptr, napi_default, nullptr};
    napi_define_properties(env, exports, 1, &property);
    const napi_property_descriptor status = {"localTrustStatus", nullptr, LocalTrustStatus, nullptr, nullptr, nullptr, napi_default, nullptr};
    napi_define_properties(env, exports, 1, &status); return exports;
}
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
