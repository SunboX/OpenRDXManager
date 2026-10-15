// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static _Atomic bool rdx_acquisition_diagnostics_enabled = false;

/** Emits one private fixed progress record without changing caller errno or results. */
static void rdx_emit_acquisition_progress(
    FILE *stream, rdx_acquisition_stage stage, rdx_acquisition_progress_event event
);

/** Records only an opted-in native boundary, never completion status or device values. */
void rdx_record_acquisition_progress(
    rdx_acquisition_stage stage, rdx_acquisition_progress_event event
) {
    rdx_emit_acquisition_progress(stderr, stage, event);
}

/** Enables fixed acquisition diagnostics only for an explicitly opted-in process. */
void rdx_macos_enable_acquisition_diagnostics(void) {
    atomic_store_explicit(&rdx_acquisition_diagnostics_enabled, true, memory_order_relaxed);
}

/** Maps only a closed internal stage enumeration to printable diagnostic text. */
static const char *rdx_acquisition_stage_name(rdx_acquisition_stage stage) {
    switch (stage) {
        case RDX_ACQUIRE_LEGACY_PLUGIN: return "legacy-create-plugin";
        case RDX_ACQUIRE_LEGACY_INTERFACE: return "legacy-query-interface";
        case RDX_ACQUIRE_LEGACY_EXCLUSIVE: return "legacy-obtain-exclusive";
        case RDX_ACQUIRE_USB_AUTHORITY: return "usb-check-authority";
        case RDX_ACQUIRE_USB_ANCESTOR: return "usb-find-ancestor";
        case RDX_ACQUIRE_USB_IDENTITY: return "usb-validate-identity";
        case RDX_ACQUIRE_USB_CAPTURE: return "usb-capture-device";
        case RDX_ACQUIRE_USB_CONFIGURE: return "usb-configure-device";
        case RDX_ACQUIRE_USB_FIND_INTERFACE: return "usb-find-bot-interface";
        case RDX_ACQUIRE_USB_OPEN_INTERFACE: return "usb-open-interface";
        case RDX_ACQUIRE_USB_PIPE_DESCRIPTORS: return "usb-pipe-descriptors";
        case RDX_ACQUIRE_USB_PIPE_ENDPOINTS: return "usb-pipe-endpoints";
        case RDX_ACQUIRE_USB_PIPE_IN: return "usb-open-bulk-in";
        case RDX_ACQUIRE_USB_PIPE_OUT: return "usb-open-bulk-out";
        case RDX_ACQUIRE_USB_ALLOCATION: return "usb-allocate-lease";
        case RDX_ACQUIRE_USB_EXCEPTION: return "usb-acquire-exception";
        default: return "unknown";
    }
}

/** Emits one bounded enum-only boundary; diagnostic I/O never replaces caller errno. */
static void rdx_emit_acquisition_progress(
    FILE *stream, rdx_acquisition_stage stage, rdx_acquisition_progress_event event
) {
    const int saved_errno = errno;
    if (!atomic_load_explicit(&rdx_acquisition_diagnostics_enabled, memory_order_relaxed) ||
        (unsigned int)stage >= RDX_ACQUIRE_USB_EXCEPTION ||
        (event != RDX_ACQUIRE_ENTER && event != RDX_ACQUIRE_RETURN)) {
        return;
    }
    char output[192];
    int length = snprintf(output, sizeof(output),
        "{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"%s\",\"event\":\"%s\"}\n",
        rdx_acquisition_stage_name(stage), event == RDX_ACQUIRE_ENTER ? "enter" : "return");
    if (length > 0 && (size_t)length < sizeof(output)) {
        (void)fwrite(output, 1, (size_t)length, stream);
        (void)fflush(stream);
    }
    errno = saved_errno;
}

/** Formats fixed names and numeric native codes, never NSError text or device data. */
static int rdx_format_acquisition_diagnostic(
    char output[256], rdx_acquisition_stage stage, rdx_macos_status status,
    rdx_acquisition_code_kind kind, int64_t native_code
) {
    const char *code_kind = "none";
    switch (kind) {
        case RDX_ACQUIRE_CODE_IORETURN: code_kind = "ioreturn"; break;
        case RDX_ACQUIRE_CODE_HRESULT: code_kind = "hresult"; break;
        case RDX_ACQUIRE_CODE_NSERROR: code_kind = "nserror"; break;
        default: break;
    }
    return snprintf(output, 256,
        "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"%s\","
        "\"nativeStatus\":%" PRIu32 ",\"nativeCodeKind\":\"%s\",\"nativeCode\":%" PRId64 "}\n",
        rdx_acquisition_stage_name(stage), status, code_kind, native_code);
}

/** Emits at most one bounded line for an opted-in acquisition boundary. */
void rdx_record_acquisition_diagnostic(
    rdx_acquisition_stage stage, rdx_macos_status status,
    rdx_acquisition_code_kind kind, int64_t native_code
) {
    if (!atomic_load_explicit(&rdx_acquisition_diagnostics_enabled, memory_order_relaxed)) {
        return;
    }
    char output[256];
    int length = rdx_format_acquisition_diagnostic(output, stage, status, kind, native_code);
    if (length > 0 && (size_t)length < sizeof(output)) {
        (void)fwrite(output, 1, (size_t)length, stderr);
        (void)fflush(stderr);
    }
}

/** Flushes one fixed numeric-class record before native capture cleanup can terminate the worker. */
void rdx_record_interface_error_evidence(const rdx_interface_error_evidence *evidence) {
    if (evidence == NULL || !atomic_load_explicit(&rdx_acquisition_diagnostics_enabled,
        memory_order_relaxed)) { return; }
    char output[256];
    int length = snprintf(output, sizeof(output),
        "{\"diagnostic\":\"interface-init-evidence\",\"status\":%" PRIu32
        ",\"domain\":%u,\"code\":%u,\"reason\":%u,\"underDomain\":%u,\"underCode\":%u}\n",
        evidence->status, evidence->domain, evidence->code, evidence->reason,
        evidence->under_domain, evidence->under_code);
    if (length > 0 && (size_t)length < sizeof(output)) {
        (void)fwrite(output, 1, (size_t)length, stderr);
        (void)fflush(stderr);
    }
}

#if defined(RDX_MACOS_TEST_HOOKS)
/** Exercises the actual emitter using a private temporary stream, with no stderr redirection. */
static bool rdx_test_acquisition_progress(void) {
    FILE *stream = tmpfile();
    if (stream == NULL) { return false; }
    errno = EDOM;
    rdx_emit_acquisition_progress(stream, RDX_ACQUIRE_USB_OPEN_INTERFACE, RDX_ACQUIRE_ENTER);
    bool valid = errno == EDOM && ftell(stream) == 0;
    atomic_store_explicit(&rdx_acquisition_diagnostics_enabled, true, memory_order_relaxed);
    errno = ERANGE;
    rdx_emit_acquisition_progress(stream, RDX_ACQUIRE_USB_OPEN_INTERFACE, RDX_ACQUIRE_ENTER);
    valid = valid && errno == ERANGE;
    rdx_emit_acquisition_progress(stream, RDX_ACQUIRE_USB_OPEN_INTERFACE, RDX_ACQUIRE_RETURN);
    rdx_emit_acquisition_progress(stream, (rdx_acquisition_stage)999, RDX_ACQUIRE_ENTER);
    rdx_emit_acquisition_progress(stream, RDX_ACQUIRE_USB_OPEN_INTERFACE, (rdx_acquisition_progress_event)0);
    FILE *read_only = fopen("/dev/null", "r");
    if (read_only != NULL) {
        errno = EDOM;
        rdx_emit_acquisition_progress(read_only, RDX_ACQUIRE_USB_CAPTURE, RDX_ACQUIRE_ENTER);
        valid = valid && ferror(read_only) != 0 && errno == EDOM;
        fclose(read_only);
    } else { valid = false; }
    atomic_store_explicit(&rdx_acquisition_diagnostics_enabled, false, memory_order_relaxed);
    rewind(stream);
    char actual[512] = {0};
    size_t length = fread(actual, 1, sizeof(actual) - 1, stream);
    const char *expected =
        "{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"usb-open-interface\",\"event\":\"enter\"}\n"
        "{\"diagnostic\":\"native-acquisition-progress\",\"substage\":\"usb-open-interface\",\"event\":\"return\"}\n";
    valid = valid && length == strlen(expected) && strcmp(actual, expected) == 0;
    // Every eligible fixed boundary fits in one parser line, including a full successful path.
    atomic_store_explicit(&rdx_acquisition_diagnostics_enabled, true, memory_order_relaxed);
    for (unsigned int stage = 0; stage < RDX_ACQUIRE_USB_EXCEPTION; ++stage) {
        rdx_emit_acquisition_progress(stream, (rdx_acquisition_stage)stage, RDX_ACQUIRE_ENTER);
        rdx_emit_acquisition_progress(stream, (rdx_acquisition_stage)stage, RDX_ACQUIRE_RETURN);
    }
    atomic_store_explicit(&rdx_acquisition_diagnostics_enabled, false, memory_order_relaxed);
    fseek(stream, (long)length, SEEK_SET);
    unsigned int lines = 0;
    while (fgets(actual, sizeof(actual), stream) != NULL) {
        size_t count = strlen(actual);
        valid = valid && count < 192 && count > 0 && actual[count - 1] == '\n' &&
            strstr(actual, "\"substage\":\"unknown\"") == NULL;
        lines += 1;
    }
    valid = valid && lines == 2 * RDX_ACQUIRE_USB_EXCEPTION;
    fclose(stream);
    return valid;
}

/** Proves default-off output and bounded enum-only formatting without native I/O. */
bool rdx_macos_test_acquisition_diagnostics_contract(void) {
    if (atomic_load_explicit(&rdx_acquisition_diagnostics_enabled, memory_order_relaxed)) {
        return false;
    }
    char output[256];
    for (unsigned int stage = 0; stage <= RDX_ACQUIRE_USB_EXCEPTION; ++stage) {
        int length = rdx_format_acquisition_diagnostic(output, (rdx_acquisition_stage)stage,
            UINT32_MAX, RDX_ACQUIRE_CODE_NSERROR, INT64_MIN);
        if (length <= 0 || length >= 256 || output[length - 1] != '\n' ||
            strstr(output, "\"nativeCodeKind\":\"nserror\"") == NULL) {
            return false;
        }
    }
    int length = rdx_format_acquisition_diagnostic(output, RDX_ACQUIRE_USB_CAPTURE,
        RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE, RDX_ACQUIRE_CODE_IORETURN, INT64_MAX);
    return rdx_test_acquisition_progress() && length > 0 && length < 256 &&
        strstr(output, "\"substage\":\"usb-capture-device\"") != NULL &&
        strstr(output, "\"nativeCodeKind\":\"ioreturn\"") != NULL;
}
#endif
