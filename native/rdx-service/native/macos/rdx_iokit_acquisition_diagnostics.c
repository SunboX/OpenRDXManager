// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static _Atomic bool rdx_acquisition_diagnostics_enabled = false;

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

#if defined(RDX_MACOS_TEST_HOOKS)
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
    return length > 0 && length < 256 &&
        strstr(output, "\"substage\":\"usb-capture-device\"") != NULL &&
        strstr(output, "\"nativeCodeKind\":\"ioreturn\"") != NULL;
}
#endif
