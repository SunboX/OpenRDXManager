// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "windows_log_files.h"
#include "windows_mcp_files.h"

#include <cmath>
#include <cstring>
#include <utility>

namespace openrdx::logs {
namespace {

enum class Operation { Prepare, OpenAppend, OpenRead, Remove, Rotate, Stat, Read, Append, Close,
                       McpPrepare, McpReadSettings, McpWriteSettings, McpEnsureToken, McpReadToken };
Operation kPrepare = Operation::Prepare, kOpenAppend = Operation::OpenAppend,
          kOpenRead = Operation::OpenRead, kRemove = Operation::Remove, kRotate = Operation::Rotate,
          kStat = Operation::Stat, kRead = Operation::Read, kAppend = Operation::Append,
          kClose = Operation::Close;
Operation kMcpPrepare = Operation::McpPrepare, kMcpReadSettings = Operation::McpReadSettings,
          kMcpWriteSettings = Operation::McpWriteSettings, kMcpEnsureToken = Operation::McpEnsureToken,
          kMcpReadToken = Operation::McpReadToken;
constexpr napi_type_tag kRootTag{0x4F5244584C4F4752, 0xC334B538389743D1};
constexpr napi_type_tag kFileTag{0x4F5244584C4F4746, 0x9295D161493B49AF};
constexpr napi_type_tag kMcpTag{0x4F5244584D435052, 0x4A159AAC71293EA1};

/** Opaque lifetime shared by JavaScript wrappers and pending native jobs. */
struct Box {
  std::shared_ptr<Root> root;
  std::shared_ptr<File> file;
  std::shared_ptr<McpStore> mcp;
};

/** One bounded asynchronous filesystem operation; never retains a JavaScript buffer pointer. */
struct Job {
  napi_async_work work = nullptr;
  napi_deferred deferred = nullptr;
  Operation operation = Operation::Prepare;
  Box owner;
  bool backup = false;
  size_t length = 0, position = 0, reservation = 0;
  std::vector<std::uint8_t> bytes;
  std::shared_ptr<File> opened;
  std::uint64_t size = 0;
  const char* error = nullptr;
  /** Clears copied credential/input/result bytes after success or failure. */
  ~Job() { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); }
};

std::mutex budget_mutex;
size_t pending_count = 0, pending_bytes = 0;

/** Rejects failed N-API work instead of using uninitialized values. */
void Check(napi_status status) {
  if (status != napi_ok) throw Failure{"windows-log-binding-failed"};
}

/** Creates a path-free JavaScript error with an optional stable ENOENT code. */
napi_value Error(napi_env env, const char* code) {
  napi_value message, label, error;
  Check(napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &message));
  Check(napi_create_string_utf8(env, code, NAPI_AUTO_LENGTH, &label));
  Check(napi_create_error(env, label, message, &error));
  return error;
}

/** Produces one strict boolean property on native proof objects. */
void Boolean(napi_env env, napi_value object, const char* name, bool flag) {
  napi_value value;
  Check(napi_get_boolean(env, flag, &value));
  Check(napi_set_named_property(env, object, name, value));
}

/** Finalizes only wrapper ownership; an in-flight job keeps the native state alive. */
void Finalize(napi_env, void* data, void*) { delete static_cast<Box*>(data); }

/** Checks the exact receiver brand before reading its opaque native wrapper. */
Box* Unwrap(napi_env env, napi_value value, const napi_type_tag& tag) {
  bool branded = false;
  Check(napi_check_object_type_tag(env, value, &tag, &branded));
  if (!branded) throw Failure{"windows-log-receiver-invalid"};
  void* data = nullptr;
  Check(napi_unwrap(env, value, &data));
  if (!data) throw Failure{"windows-log-receiver-invalid"};
  return static_cast<Box*>(data);
}

/** Reads an exact bounded integer without truncation or unsigned wrapping. */
size_t Integer(napi_env env, napi_value value) {
  double number = 0;
  Check(napi_get_value_double(env, value, &number));
  if (!std::isfinite(number) || number < 0 || number > kMaximumRead || std::floor(number) != number)
    throw Failure{"windows-log-arguments-invalid"};
  return static_cast<size_t>(number);
}

/** Reserves one process-wide bounded pending operation and copied-buffer budget. */
void Reserve(Job* job) {
  job->reservation = 1024 + job->bytes.size() + job->length;
  std::lock_guard lock(budget_mutex);
  constexpr size_t maximum = 40 * 1024 * 1024;
  if (pending_count >= 64 || job->reservation > maximum - pending_bytes)
    throw Failure{"windows-log-resource-limit"};
  ++pending_count;
  pending_bytes += job->reservation;
}

/** Releases admission only after the worker no longer owns its I/O buffers. */
void Release(Job* job) {
  std::lock_guard lock(budget_mutex);
  --pending_count;
  pending_bytes -= job->reservation;
}

/** Executes file and ACL work off the Electron main thread, retaining exact ownership. */
void Execute(napi_env, void* data) {
  auto* job = static_cast<Job*>(data);
  try {
    switch (job->operation) {
      case Operation::Prepare: job->owner.root->prepare(); break;
      case Operation::OpenAppend: job->opened = job->owner.root->open(false, true); break;
      case Operation::OpenRead: job->opened = job->owner.root->open(job->backup, false); break;
      case Operation::Remove: job->owner.root->remove_backup(); break;
      case Operation::Rotate: job->owner.root->rotate(); break;
      case Operation::Stat: job->size = job->owner.file->size(); break;
      case Operation::Read: job->bytes = job->owner.file->read(job->length, job->position); break;
      case Operation::Append: job->owner.file->append(job->bytes); break;
      case Operation::Close: job->owner.file->close(); break;
      case Operation::McpPrepare: job->owner.mcp->prepare(); break;
      case Operation::McpReadSettings: job->bytes = job->owner.mcp->read(false); break;
      case Operation::McpReadToken: job->bytes = job->owner.mcp->read(true); break;
      case Operation::McpWriteSettings: job->owner.mcp->write_settings(job->bytes); break;
      case Operation::McpEnsureToken: {
        auto token = job->owner.mcp->ensure_token(job->bytes);
        SecureZeroMemory(job->bytes.data(), job->bytes.size());
        job->bytes = std::move(token);
        break;
      }
    }
  } catch (const Failure& failure) { job->error = failure.code; }
  catch (...) { job->error = "windows-log-resource-failed"; }
}

/** Queues a branded file operation after copying and validating its arguments. */
napi_value FileCall(napi_env env, napi_callback_info info);

/** Creates an opaque native file exposing only bounded descriptor operations. */
napi_value WrapFile(napi_env env, const std::shared_ptr<File>& file) {
  auto box = std::make_unique<Box>();
  box->file = file;
  napi_value object;
  Check(napi_create_object(env, &object));
  Check(napi_type_tag_object(env, object, &kFileTag));
  Check(napi_wrap(env, object, box.get(), Finalize, nullptr, nullptr));
  box.release();
  napi_property_descriptor methods[] = {
      {"stat", nullptr, FileCall, nullptr, nullptr, nullptr, napi_default, &kStat},
      {"read", nullptr, FileCall, nullptr, nullptr, nullptr, napi_default, &kRead},
      {"append", nullptr, FileCall, nullptr, nullptr, nullptr, napi_default, &kAppend},
      {"close", nullptr, FileCall, nullptr, nullptr, nullptr, napi_default, &kClose}};
  Check(napi_define_properties(env, object, 4, methods));
  return object;
}

/** Creates proof only after successful native verification of the exact operation. */
napi_value Result(napi_env env, Job* job) {
  napi_value result;
  if (job->operation == Operation::Read || job->operation == Operation::McpReadSettings ||
      job->operation == Operation::McpReadToken || job->operation == Operation::McpEnsureToken) {
    Check(napi_create_buffer_copy(env, job->bytes.size(), job->bytes.data(), nullptr, &result));
    return result;
  }
  Check(napi_create_object(env, &result));
  if (job->operation == Operation::Stat) {
    if (job->size > 9'007'199'254'740'991ULL) throw Failure{"windows-log-size-invalid"};
    napi_value size;
    Check(napi_create_double(env, static_cast<double>(job->size), &size));
    Check(napi_set_named_property(env, result, "size", size));
    Boolean(env, result, "regular", true);
  } else if (job->operation == Operation::Prepare || job->operation == Operation::Remove ||
             job->operation == Operation::Rotate || job->opened) {
    Boolean(env, result, "reparsePoint", false);
    Boolean(env, result, "userOnlyDacl", true);
    if (job->operation == Operation::Prepare) Boolean(env, result, "directory", true);
    if (job->operation == Operation::Remove) Boolean(env, result, "removed", true);
    if (job->operation == Operation::Rotate || job->opened) Boolean(env, result, "noFollowVerified", true);
    if (job->opened) Check(napi_set_named_property(env, result, "handle", WrapFile(env, job->opened)));
  }
  return result;
}

/** Settles one asynchronous operation and releases all worker-owned resources. */
void Complete(napi_env env, napi_status status, void* data) {
  std::unique_ptr<Job> job(static_cast<Job*>(data));
  Release(job.get());
  napi_delete_async_work(env, job->work);
  try {
    if (status != napi_ok && !job->error) job->error = "windows-log-work-failed";
    if (job->error) Check(napi_reject_deferred(env, job->deferred, Error(env, job->error)));
    else Check(napi_resolve_deferred(env, job->deferred, Result(env, job.get())));
  } catch (const Failure& failure) {
    napi_reject_deferred(env, job->deferred, Error(env, failure.code));
  } catch (...) {
    napi_reject_deferred(env, job->deferred, Error(env, "windows-log-resource-failed"));
  }
}

/** Creates the awaitable boundary before starting bounded native worker execution. */
napi_value Queue(napi_env env, std::unique_ptr<Job> job) {
  napi_value promise, name;
  Check(napi_create_string_utf8(env, "OpenRDXPrivateLog", NAPI_AUTO_LENGTH, &name));
  Check(napi_create_promise(env, &job->deferred, &promise));
  Reserve(job.get());
  try {
    Check(napi_create_async_work(env, nullptr, name, Execute, Complete, job.get(), &job->work));
    Check(napi_queue_async_work(env, job->work));
  } catch (...) {
    if (job->work) napi_delete_async_work(env, job->work);
    Release(job.get());
    throw;
  }
  job.release();
  return promise;
}

napi_value FileCall(napi_env env, napi_callback_info info) {
  try {
    napi_value args[3], receiver;
    size_t count = 3;
    void* operation = nullptr;
    Check(napi_get_cb_info(env, info, &count, args, &receiver, &operation));
    auto job = std::make_unique<Job>();
    job->operation = *static_cast<Operation*>(operation);
    job->owner = *Unwrap(env, receiver, kFileTag);
    if (job->operation == Operation::Read && count == 2) {
      job->length = Integer(env, args[0]);
      job->position = Integer(env, args[1]);
    } else if (job->operation == Operation::Append && count == 1) {
      bool buffer = false;
      Check(napi_is_buffer(env, args[0], &buffer));
      if (!buffer) throw Failure{"windows-log-arguments-invalid"};
      void* bytes = nullptr;
      size_t length = 0;
      Check(napi_get_buffer_info(env, args[0], &bytes, &length));
      if (length > kMaximumRead) throw Failure{"windows-log-resource-limit"};
      if (length) job->bytes.assign(static_cast<std::uint8_t*>(bytes),
                                    static_cast<std::uint8_t*>(bytes) + length);
    } else if (count != 0 || (job->operation != Operation::Stat && job->operation != Operation::Close)) {
      throw Failure{"windows-log-arguments-invalid"};
    }
    return Queue(env, std::move(job));
  } catch (const Failure& failure) { napi_throw_error(env, failure.code, failure.code); }
  catch (...) { napi_throw_error(env, nullptr, "windows-log-resource-failed"); }
  return nullptr;
}

/** Dispatches only the fixed current/backup filename operations on a branded root. */
napi_value RootCall(napi_env env, napi_callback_info info) {
  try {
    napi_value args[2], receiver;
    size_t count = 2;
    void* operation = nullptr;
    Check(napi_get_cb_info(env, info, &count, args, &receiver, &operation));
    auto job = std::make_unique<Job>();
    job->operation = *static_cast<Operation*>(operation);
    const bool mcp = job->operation >= Operation::McpPrepare;
    job->owner = *Unwrap(env, receiver, mcp ? kMcpTag : kRootTag);
    if (mcp && (job->operation == Operation::McpWriteSettings || job->operation == Operation::McpEnsureToken)) {
      if (count != 1) throw Failure{"windows-mcp-arguments-invalid"};
      bool buffer = false;
      Check(napi_is_buffer(env, args[0], &buffer));
      if (!buffer) throw Failure{"windows-mcp-arguments-invalid"};
      void* bytes = nullptr;
      size_t length = 0;
      Check(napi_get_buffer_info(env, args[0], &bytes, &length));
      if (!length || length > (job->operation == Operation::McpEnsureToken ? 65U : 4096U))
        throw Failure{"windows-mcp-arguments-invalid"};
      job->bytes.assign(static_cast<std::uint8_t*>(bytes), static_cast<std::uint8_t*>(bytes) + length);
    } else if (job->operation == Operation::OpenRead && count == 1)
      Check(napi_get_value_bool(env, args[0], &job->backup));
    else if (count != 0 || job->operation == Operation::OpenRead)
      throw Failure{"windows-log-arguments-invalid"};
    if (job->operation == Operation::McpReadSettings) job->length = 4097;
    if (job->operation == Operation::McpReadToken || job->operation == Operation::McpEnsureToken)
      job->length = 66;
    return Queue(env, std::move(job));
  } catch (const Failure& failure) { napi_throw_error(env, failure.code, failure.code); }
  catch (...) { napi_throw_error(env, nullptr, "windows-log-resource-failed"); }
  return nullptr;
}

/** Captures one fixed main-owned local root; no renderer-authored paths are accepted later. */
napi_value Create(napi_env env, napi_callback_info info) {
  try {
    napi_value args[2], receiver;
    void* factory = nullptr;
    size_t count = 2, length = 0;
    Check(napi_get_cb_info(env, info, &count, args, &receiver, &factory));
    const bool mcp = factory == &kMcpPrepare;
    if (count != 1) throw Failure{"windows-log-arguments-invalid"};
    Check(napi_get_value_string_utf16(env, args[0], nullptr, 0, &length));
    if (!length || length > 16'000) throw Failure{"windows-log-path-invalid"};
    std::vector<char16_t> units(length + 1);
    Check(napi_get_value_string_utf16(env, args[0], units.data(), units.size(), &length));
    static_assert(sizeof(wchar_t) == sizeof(char16_t));
    auto box = std::make_unique<Box>();
    const std::wstring path(reinterpret_cast<wchar_t*>(units.data()), length);
    if (mcp) box->mcp = std::make_shared<McpStore>(path);
    else box->root = std::make_shared<Root>(path);
    napi_value object;
    Check(napi_create_object(env, &object));
    Check(napi_type_tag_object(env, object, mcp ? &kMcpTag : &kRootTag));
    Check(napi_wrap(env, object, box.get(), Finalize, nullptr, nullptr));
    box.release();
    napi_property_descriptor methods[] = {
        {"prepare", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kPrepare},
        {"openAppend", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kOpenAppend},
        {"openRead", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kOpenRead},
        {"removeBackup", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kRemove},
        {"rotate", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kRotate}};
    napi_property_descriptor mcp_methods[] = {
        {"prepare", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kMcpPrepare},
        {"readSettings", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kMcpReadSettings},
        {"writeSettings", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kMcpWriteSettings},
        {"ensureToken", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kMcpEnsureToken},
        {"readToken", nullptr, RootCall, nullptr, nullptr, nullptr, napi_default, &kMcpReadToken}};
    Check(napi_define_properties(env, object, 5, mcp ? mcp_methods : methods));
    return object;
  } catch (const Failure& failure) { napi_throw_error(env, failure.code, failure.code); }
  catch (...) { napi_throw_error(env, nullptr, "windows-log-resource-failed"); }
  return nullptr;
}

}  // namespace

napi_status RegisterLogFiles(napi_env env, napi_value exports) {
  napi_property_descriptor factories[] = {
      {"createLogSecurity", nullptr, Create, nullptr, nullptr, nullptr, napi_default, nullptr},
      {"createMcpStorage", nullptr, Create, nullptr, nullptr, nullptr, napi_default, &kMcpPrepare}};
  return napi_define_properties(env, exports, 2, factories);
}

}  // namespace openrdx::logs
