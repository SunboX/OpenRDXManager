// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <Foundation/Foundation.h>
#include <ServiceManagement/ServiceManagement.h>
#include <Security/Security.h>
#include <sys/stat.h>
#include <errno.h>
#include <node_api.h>

namespace {

constexpr const char *kDaemonPlistName = "com.openrdx.hardware.plist";

// The public NSString constant was introduced in the macOS 15 SDK. Its error
// domain string also identifies SMAppService errors on our macOS 13 baseline,
// without adding a symbol that older SDKs/runtimes cannot resolve.
NSString * const kAppServiceErrorDomain = @"SMAppServiceErrorDomain";

/** Throws a fixed JavaScript type error and returns null. */
napi_value ThrowTypeError(napi_env env) {
    napi_throw_type_error(env, nullptr, "service-management-arguments-invalid");
    return nullptr;
}

/** Requires a native export to be invoked with exactly zero arguments. */
bool RequireZeroArguments(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argument;
    if (napi_get_cb_info(env, info, &argc, &argument, nullptr, nullptr) != napi_ok) {
        napi_throw_error(env, nullptr, "service-management-call-failed");
        return false;
    }
    if (argc != 0) {
        ThrowTypeError(env);
        return false;
    }
    return true;
}

/** Converts one fixed ASCII status token into a JavaScript string. */
napi_value StateString(napi_env env, const char *state) {
    napi_value value;
    if (napi_create_string_utf8(env, state, NAPI_AUTO_LENGTH, &value) != napi_ok) {
        napi_throw_error(env, nullptr, "service-management-result-failed");
        return nullptr;
    }
    return value;
}

/**
 * Selects the sealed installer mode without taking renderer, environment or path
 * inputs. A local policy artifact can only force verification, never readiness.
 * Unsigned and ad-hoc portable copies require the administrator-owned installer.
 */
const char *InstalledMode() {
    id mode = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"OpenRDXInstallationMode"];
    if (mode != nil) return [mode isEqual:@"local"] ? "local" : "invalid";
    struct stat metadata;
    if (lstat("/Library/Application Support/OpenRDXManager/LocalTrust", &metadata) == 0 || errno != ENOENT) {
        return "local";
    }
    SecCodeRef code = nullptr;
    SecRequirementRef requirement = nullptr;
    const CFStringRef expression = CFSTR("anchor apple generic and identifier \"com.openrdx.manager\"");
    const OSStatus found = SecCodeCopySelf(kSecCSDefaultFlags, &code);
    const OSStatus parsed = SecRequirementCreateWithString(expression, kSecCSDefaultFlags, &requirement);
    const bool signedManager = found == errSecSuccess && parsed == errSecSuccess &&
        SecCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, requirement) == errSecSuccess;
    if (requirement != nullptr) CFRelease(requirement);
    if (code != nullptr) CFRelease(code);
    return signedManager ? "signed" : "local";
}

/** Returns only the installer-owned mode selector, with no readiness claim. */
napi_value InstallationMode(napi_env env, napi_callback_info info) {
    if (!RequireZeroArguments(env, info)) return nullptr;
    @autoreleasepool { return StateString(env, InstalledMode()); }
}

/** Returns the one fixed launch-daemon service descriptor. */
SMAppService *DaemonService() {
    return [SMAppService daemonServiceWithPlistName:@(kDaemonPlistName)];
}

/** Maps the documented ServiceManagement status enumeration to a closed token. */
const char *MapStatus(SMAppServiceStatus status) {
    switch (status) {
    case SMAppServiceStatusNotRegistered:
        return "not-registered";
    case SMAppServiceStatusEnabled:
        return "enabled";
    case SMAppServiceStatusRequiresApproval:
        return "requires-approval";
    case SMAppServiceStatusNotFound:
        return "not-found";
    }
    return "registration-failed";
}

/** Maps a registration error without returning native descriptions or paths. */
const char *MapRegistrationError(NSError *error) {
    if ([error.domain isEqualToString:kAppServiceErrorDomain]) {
        switch (error.code) {
        case kSMErrorInvalidSignature:
            return "invalid-signature";
        case kSMErrorLaunchDeniedByUser:
            return "requires-approval";
        case kSMErrorJobNotFound:
            return "not-found";
        case kSMErrorAlreadyRegistered:
            return MapStatus(DaemonService().status);
        default:
            break;
        }
    }
    return "registration-failed";
}

/** Returns the current fixed daemon status. */
napi_value Status(napi_env env, napi_callback_info info) {
    if (!RequireZeroArguments(env, info)) {
        return nullptr;
    }
    @autoreleasepool {
        if (strcmp(InstalledMode(), "signed") != 0) return StateString(env, "installer-required");
        return StateString(env, MapStatus(DaemonService().status));
    }
}

/** Registers the fixed daemon and returns only a closed state token. */
napi_value RegisterService(napi_env env, napi_callback_info info) {
    if (!RequireZeroArguments(env, info)) {
        return nullptr;
    }
    @autoreleasepool {
        if (strcmp(InstalledMode(), "signed") != 0) return StateString(env, "installer-required");
        NSError *error = nil;
        SMAppService *service = DaemonService();
        if ([service registerAndReturnError:&error]) {
            return StateString(env, MapStatus(service.status));
        }
        return StateString(env, MapRegistrationError(error));
    }
}

/** Unregisters the fixed daemon and treats an already absent job idempotently. */
napi_value UnregisterService(napi_env env, napi_callback_info info) {
    if (!RequireZeroArguments(env, info)) {
        return nullptr;
    }
    @autoreleasepool {
        if (strcmp(InstalledMode(), "signed") != 0) return StateString(env, "installer-required");
        NSError *error = nil;
        SMAppService *service = DaemonService();
        if ([service unregisterAndReturnError:&error]) {
            return StateString(env, MapStatus(service.status));
        }
        if ([error.domain isEqualToString:kAppServiceErrorDomain] && error.code == kSMErrorJobNotFound) {
            return StateString(env, "not-registered");
        }
        return StateString(env, MapRegistrationError(error));
    }
}

/** Opens the system-owned Login Items approval pane after a user action. */
napi_value OpenApprovalSettings(napi_env env, napi_callback_info info) {
    if (!RequireZeroArguments(env, info)) {
        return nullptr;
    }
    @autoreleasepool {
        if (strcmp(InstalledMode(), "signed") != 0) {
            napi_value denied;
            napi_get_boolean(env, false, &denied);
            return denied;
        }
        [SMAppService openSystemSettingsLoginItems];
    }
    napi_value result;
    if (napi_get_boolean(env, true, &result) != napi_ok) {
        napi_throw_error(env, nullptr, "service-management-result-failed");
        return nullptr;
    }
    return result;
}

/** Defines the complete fixed N-API export surface. */
napi_value Initialize(napi_env env, napi_value exports) {
    const napi_property_descriptor properties[] = {
        {"installationMode", nullptr, InstallationMode, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"status", nullptr, Status, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"registerService", nullptr, RegisterService, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"unregisterService", nullptr, UnregisterService, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"openApprovalSettings", nullptr, OpenApprovalSettings, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) {
        napi_throw_error(env, nullptr, "service-management-export-failed");
        return nullptr;
    }
    return exports;
}

} // namespace

NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)
