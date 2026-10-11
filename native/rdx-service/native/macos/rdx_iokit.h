// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef OPENRDX_RDX_IOKIT_H
#define OPENRDX_RDX_IOKIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDX_MACOS_ABI_VERSION UINT32_C(4)
#define RDX_MACOS_MAX_CANDIDATES UINT32_C(128)
#define RDX_MACOS_MAX_TEXT_BYTES UINT32_C(128)
#define RDX_MACOS_MAX_TRANSFER_BYTES UINT32_C(4096)
#define RDX_MACOS_MAX_SENSE_BYTES UINT32_C(252)
#define RDX_MACOS_MAX_MEDIA UINT32_C(32)
#define RDX_MACOS_UUID_BYTES UINT32_C(37)
#define RDX_MACOS_MAX_MOUNT_PATH_BYTES UINT32_C(1024)
#define RDX_MACOS_MAX_BSD_NAME_BYTES UINT32_C(64)
#define RDX_MACOS_MAX_DA_CONTEXTS UINT32_C(8)

typedef uint32_t rdx_macos_status;
enum {
    RDX_MACOS_STATUS_OK = 0,
    RDX_MACOS_STATUS_INVALID_ARGUMENT = 1,
    RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE = 2,
    RDX_MACOS_STATUS_ACCESS_DENIED = 3,
    RDX_MACOS_STATUS_BUSY = 4,
    RDX_MACOS_STATUS_TIMED_OUT = 5,
    RDX_MACOS_STATUS_DEVICE_REMOVED = 6,
    RDX_MACOS_STATUS_ENUMERATION_FAILED = 7,
    RDX_MACOS_STATUS_RESOURCE_LIMIT = 8,
    RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE = 9,
    RDX_MACOS_STATUS_NATIVE_FAILURE = 10
};

enum {
    RDX_MACOS_FILESYSTEM_EXFAT = 1
};

typedef uint32_t rdx_macos_result_kind;
enum {
    RDX_MACOS_RESULT_ENUMERATION = 1,
    RDX_MACOS_RESULT_SCSI = 2,
    RDX_MACOS_RESULT_MAPPING = 3,
    RDX_MACOS_RESULT_HOST_OPERATION = 4
};

typedef uint32_t rdx_macos_operation_kind;
enum {
    RDX_MACOS_OPERATION_SELF_TEST = 1,
    RDX_MACOS_OPERATION_LED_ON = 2,
    RDX_MACOS_OPERATION_LED_OFF = 3,
    RDX_MACOS_OPERATION_UNIT_RESET = 4,
    RDX_MACOS_OPERATION_INQUIRY_STANDARD = 5,
    RDX_MACOS_OPERATION_INQUIRY_DEVICE_IDENTIFICATION = 6,
    RDX_MACOS_OPERATION_LOG_SENSE_DRIVE = 7,
    RDX_MACOS_OPERATION_LOG_SENSE_CARTRIDGE = 8,
    RDX_MACOS_OPERATION_MODE_SENSE_CAPABILITIES = 9,
    RDX_MACOS_OPERATION_MODE_SENSE_DRIVE = 10,
    RDX_MACOS_OPERATION_MODE_SENSE_SATA = 11,
    RDX_MACOS_OPERATION_SECURITY_IN_0010 = 12,
    RDX_MACOS_OPERATION_SECURITY_IN_0020 = 13,
    RDX_MACOS_OPERATION_SECURITY_IN_0021 = 14,
    RDX_MACOS_OPERATION_MODE_SELECT = 15,
    RDX_MACOS_OPERATION_FIRMWARE_CHUNK = 16,
    RDX_MACOS_OPERATION_FIRMWARE_FINALIZE = 17,
    RDX_MACOS_OPERATION_INQUIRY_MEDIA_IDENTIFICATION = 18,
    RDX_MACOS_OPERATION_INQUIRY_MEDIA_DEVICE = 19,
    RDX_MACOS_OPERATION_LOG_SENSE_TEMPERATURE = 20,
    RDX_MACOS_OPERATION_EJECT_MEDIA = 21,
    RDX_MACOS_OPERATION_VENDOR_0283_FACTORY_INFO = 22,
    RDX_MACOS_OPERATION_VENDOR_0283_USB_IDENTITY = 23,
    RDX_MACOS_OPERATION_COMPATIBILITY_RECEIVER_AUTHORIZATION = 24,
    RDX_MACOS_OPERATION_COMPATIBILITY_RECEIVER_HEADER_SETUP = 25,
    RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_FIRST = 26,
    RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_SECOND = 27,
    RDX_MACOS_OPERATION_OPENRDX_OPERATIONAL_STATE_RECORD = 28,
    RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_SECTOR_CHUNK = 29,
    RDX_MACOS_OPERATION_OPENRDX_SERIAL_CAPABILITY = 30,
    RDX_MACOS_OPERATION_OPENRDX_SET_SERIAL = 31,
    RDX_MACOS_OPERATION_OPENRDX_MECHANISM_DIAGNOSTICS = 32,
    RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RESTORE_CAPABILITY = 33,
    RDX_MACOS_OPERATION_OPENRDX_RESTORE_MANUFACTURING = 34
};

typedef struct rdx_macos_result_header {
    uint32_t abi_version;
    rdx_macos_result_kind kind;
    rdx_macos_status status;
    uint32_t reserved;
} rdx_macos_result_header;

typedef struct rdx_macos_candidate_record {
    uint64_t registry_entry_id;
    uint32_t peripheral_type;
    uint8_t has_vendor;
    uint8_t has_product;
    uint8_t has_revision;
    uint8_t has_serial;
    char vendor[RDX_MACOS_MAX_TEXT_BYTES + 1];
    char product[RDX_MACOS_MAX_TEXT_BYTES + 1];
    char revision[RDX_MACOS_MAX_TEXT_BYTES + 1];
    char serial[RDX_MACOS_MAX_TEXT_BYTES + 1];
} rdx_macos_candidate_record;

typedef struct rdx_macos_enumeration_result {
    rdx_macos_result_header header;
    uint64_t count;
    rdx_macos_candidate_record candidates[RDX_MACOS_MAX_CANDIDATES];
} rdx_macos_enumeration_result;

typedef struct rdx_macos_readiness {
    uint32_t abi_version;
    rdx_macos_status status;
    uint8_t discovery_available;
    uint8_t safe_transport_available;
    uint8_t service_metadata_present;
    uint8_t service_enabled;
    uint8_t current_process_authorized;
    uint8_t reserved[3];
    uint64_t candidate_count;
} rdx_macos_readiness;

typedef struct rdx_macos_scsi_request {
    uint32_t abi_version;
    rdx_macos_operation_kind operation;
    uint32_t timeout_ms;
    uint32_t data_length;
    uint32_t offset;
    uint8_t save_pages;
    uint8_t reserved[3];
    uint8_t data[RDX_MACOS_MAX_TRANSFER_BYTES];
} rdx_macos_scsi_request;

typedef struct rdx_macos_scsi_result {
    rdx_macos_result_header header;
    uint8_t attempted;
    uint8_t scsi_status;
    uint8_t service_response;
    uint8_t reserved;
    uint64_t realized_transfer_count;
    uint32_t data_length;
    uint32_t sense_length;
    uint8_t data[RDX_MACOS_MAX_TRANSFER_BYTES];
    uint8_t sense[RDX_MACOS_MAX_SENSE_BYTES];
} rdx_macos_scsi_result;

typedef struct rdx_macos_media_record {
    uint64_t registry_entry_id;
    uint64_t whole_registry_entry_id;
    char uuid[RDX_MACOS_UUID_BYTES];
} rdx_macos_media_record;

typedef struct rdx_macos_mapping_result {
    rdx_macos_result_header header;
    uint64_t whole_registry_entry_id;
    uint64_t media_count;
    uint64_t mounted_media_count;
    uint64_t capacity_bytes;
    uint64_t free_bytes;
    uint64_t mounted_device_id;
    uint32_t mounted_filesystem;
    uint32_t reserved_filesystem;
    uint8_t writable;
    uint8_t reserved[7];
    char mounted_path[RDX_MACOS_MAX_MOUNT_PATH_BYTES];
    rdx_macos_media_record media[RDX_MACOS_MAX_MEDIA];
} rdx_macos_mapping_result;

enum {
    RDX_MACOS_VOLUME_FILESYSTEM_UNKNOWN = 0,
    RDX_MACOS_VOLUME_FILESYSTEM_EXFAT = 1,
    RDX_MACOS_VOLUME_FILESYSTEM_NTFS = 2
};

typedef struct rdx_macos_host_operation_result {
    rdx_macos_result_header header;
    uint8_t attempted;
    uint8_t completed;
    uint8_t rejection;
    uint8_t reserved[5];
    int64_t dissenter_status;
} rdx_macos_host_operation_result;

enum {
    RDX_MACOS_HOST_REJECTION_NONE = 0,
    RDX_MACOS_HOST_REJECTION_BUSY = 1,
    RDX_MACOS_HOST_REJECTION_ACCESS_DENIED = 2
};

typedef struct rdx_macos_device rdx_macos_device;
typedef struct rdx_macos_scsi_lease rdx_macos_scsi_lease;

void rdx_macos_enable_acquisition_diagnostics(void);

rdx_macos_status rdx_macos_copy_usb_identity(
    rdx_macos_device *device,
    uint32_t *location_id,
    uint16_t *vendor_id,
    uint16_t *product_id,
    char serial[RDX_MACOS_MAX_TEXT_BYTES + 1]
);

typedef struct rdx_macos_abi_layout {
    uint32_t abi_version;
    uint32_t reserved;
    uint64_t result_header_size;
    uint64_t result_header_status_offset;
    uint64_t candidate_size;
    uint64_t candidate_registry_entry_id_offset;
    uint64_t candidate_vendor_offset;
    uint64_t candidate_serial_offset;
    uint64_t enumeration_size;
    uint64_t enumeration_count_offset;
    uint64_t enumeration_candidates_offset;
    uint64_t readiness_size;
    uint64_t readiness_candidate_count_offset;
    uint64_t scsi_request_size;
    uint64_t scsi_request_data_offset;
    uint64_t scsi_result_size;
    uint64_t scsi_result_realized_transfer_offset;
    uint64_t scsi_result_data_offset;
    uint64_t scsi_result_sense_offset;
    uint64_t media_record_size;
    uint64_t media_record_uuid_offset;
    uint64_t mapping_result_size;
    uint64_t mapping_result_media_offset;
    uint64_t host_operation_result_size;
    uint64_t host_operation_dissenter_offset;
    uint64_t resource_counters_size;
    uint64_t resource_counters_device_frees_offset;
    uint64_t abi_layout_size;
} rdx_macos_abi_layout;

typedef struct rdx_macos_resource_counters {
    uint64_t result_allocations;
    uint64_t result_frees;
    uint64_t io_acquisitions;
    uint64_t io_releases;
    uint64_t cf_acquisitions;
    uint64_t cf_releases;
    uint64_t plugin_acquisitions;
    uint64_t plugin_releases;
    uint64_t interface_acquisitions;
    uint64_t interface_releases;
    uint64_t exclusive_acquisitions;
    uint64_t exclusive_releases;
    uint64_t task_acquisitions;
    uint64_t task_releases;
    uint64_t device_allocations;
    uint64_t device_frees;
    uint64_t scsi_lease_allocations;
    uint64_t scsi_lease_frees;
    uint64_t da_registry_allocations;
    uint64_t da_registry_frees;
    uint64_t da_context_allocations;
    uint64_t da_context_frees;
    uint64_t da_contexts_outstanding;
} rdx_macos_resource_counters;

rdx_macos_status rdx_macos_enumerate(rdx_macos_enumeration_result **out_result);
rdx_macos_status rdx_macos_probe_readiness(rdx_macos_readiness *out_readiness);
bool rdx_macos_candidate_matches_rdx_hint(
    const rdx_macos_candidate_record *candidate
);
rdx_macos_status rdx_macos_open_candidate(
    const rdx_macos_candidate_record *candidate,
    rdx_macos_device **out_device
);
void rdx_macos_release_device(rdx_macos_device *device);
rdx_macos_status rdx_macos_acquire_scsi(
    rdx_macos_device *device,
    rdx_macos_scsi_lease **out_lease
);
void rdx_macos_release_scsi(rdx_macos_scsi_lease *lease);
void rdx_macos_invalidate_media_mapping(rdx_macos_device *device);
rdx_macos_status rdx_macos_execute_scsi(
    rdx_macos_scsi_lease *lease,
    const rdx_macos_scsi_request *request,
    rdx_macos_scsi_result **out_result
);
rdx_macos_status rdx_macos_map_media(
    rdx_macos_device *device,
    rdx_macos_mapping_result **out_result
);
/* Probes exact whole-media presence without retaining mapping or raw authority. */
rdx_macos_status rdx_macos_media_present_without_mapping(
    rdx_macos_device *device,
    uint8_t *out_present
);
rdx_macos_status rdx_macos_revalidate_media(rdx_macos_device *device);
rdx_macos_status rdx_macos_confirm_unmounted_mapping(rdx_macos_device *device);
bool rdx_macos_validate_mounted_fd(
    rdx_macos_device *device,
    int descriptor,
    uint64_t expected_device_id
);
rdx_macos_status rdx_macos_system_format(rdx_macos_device *device, uint32_t selector,
    const uint8_t *password, size_t password_length, rdx_macos_host_operation_result **out_result);

rdx_macos_status rdx_macos_partition_and_format(
    rdx_macos_device *device,
    uint32_t filesystem,
    uint32_t mbr_signature,
    rdx_macos_host_operation_result **out_result
);
rdx_macos_status rdx_macos_unmount(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    rdx_macos_host_operation_result **out_result
);
/* Unmounts for immediate host eject without reacquiring raw-disk authority. */
rdx_macos_status rdx_macos_unmount_for_eject(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    rdx_macos_host_operation_result **out_result
);
rdx_macos_status rdx_macos_eject(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    rdx_macos_host_operation_result **out_result
);
rdx_macos_status rdx_macos_accept_launchd_manager(
    const char *requirement_text,
    int *out_socket,
    uint32_t *out_user_id
);
rdx_macos_status rdx_macos_activate_launchd_listener(int *out_listener);
rdx_macos_status rdx_macos_accept_launchd_manager_from_listener(
    int listener,
    const char *requirement_text,
    int *out_socket,
    uint32_t *out_user_id
);
void rdx_macos_free_result(void *result);
void rdx_macos_get_abi_layout(rdx_macos_abi_layout *out_layout);
void rdx_macos_get_resource_counters(rdx_macos_resource_counters *out_counters);

#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_macos_test_hostile_inputs(void);
bool rdx_macos_test_exercise_failure_injections(void);
bool rdx_macos_test_disk_mapping_contract(void);
bool rdx_macos_test_raw_media_authority_contract(void);
bool rdx_macos_test_exfat_retained_fd_contract(void);
bool rdx_macos_test_scsi_authority_order(void);
bool rdx_macos_test_da_callback_lifecycle(void);
bool rdx_macos_test_candidate_prefilter_contract(void);
bool rdx_macos_test_usb_bot_wire_contract(void);
bool rdx_macos_test_eject_scsi_contract(void);
bool rdx_macos_test_factory_snapshot_scsi_contract(void);
/** Verifies closed documented compatibility commands without hardware access. */
bool rdx_macos_test_compatibility_setup_scsi_contract(void);
bool rdx_macos_test_acquisition_diagnostics_contract(void);
bool rdx_macos_test_usb_host_exception_contract(void);
bool rdx_macos_test_usb_host_release_order_contract(void);
bool rdx_macos_test_transport_release_mapping_invalidation(void);
bool rdx_macos_test_media_presence_without_mapping_contract(void);
void rdx_macos_test_fail_next_matching_dictionary(void);
void rdx_macos_test_succeed_next_matching_without_iterator(void);
rdx_macos_status rdx_macos_test_probe_known_non_scsi(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
