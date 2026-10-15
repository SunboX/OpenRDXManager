// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef OPENRDX_RDX_IOKIT_INTERNAL_H
#define OPENRDX_RDX_IOKIT_INTERNAL_H

#include "rdx_iokit.h"

#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <dispatch/dispatch.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>
#include <IOKit/scsi/SCSICmds_INQUIRY_Definitions.h>
#include <IOKit/scsi/SCSITaskLib.h>
#include <IOKit/storage/IOMedia.h>

#include <stdatomic.h>

typedef struct rdx_da_registry rdx_da_registry;
typedef struct rdx_macos_usb_bot_lease rdx_macos_usb_bot_lease;

typedef enum rdx_acquisition_stage {
    RDX_ACQUIRE_LEGACY_PLUGIN,
    RDX_ACQUIRE_LEGACY_INTERFACE,
    RDX_ACQUIRE_LEGACY_EXCLUSIVE,
    RDX_ACQUIRE_USB_AUTHORITY,
    RDX_ACQUIRE_USB_ANCESTOR,
    RDX_ACQUIRE_USB_IDENTITY,
    RDX_ACQUIRE_USB_CAPTURE,
    RDX_ACQUIRE_USB_CONFIGURE,
    RDX_ACQUIRE_USB_FIND_INTERFACE,
    RDX_ACQUIRE_USB_OPEN_INTERFACE,
    RDX_ACQUIRE_USB_PIPE_DESCRIPTORS,
    RDX_ACQUIRE_USB_PIPE_ENDPOINTS,
    RDX_ACQUIRE_USB_PIPE_IN,
    RDX_ACQUIRE_USB_PIPE_OUT,
    RDX_ACQUIRE_USB_ALLOCATION,
    RDX_ACQUIRE_USB_EXCEPTION
} rdx_acquisition_stage;

typedef enum rdx_acquisition_code_kind {
    RDX_ACQUIRE_CODE_NONE,
    RDX_ACQUIRE_CODE_IORETURN,
    RDX_ACQUIRE_CODE_HRESULT,
    RDX_ACQUIRE_CODE_NSERROR
} rdx_acquisition_code_kind;

void rdx_record_acquisition_diagnostic(
    rdx_acquisition_stage stage, rdx_macos_status status,
    rdx_acquisition_code_kind kind, int64_t native_code
);

typedef enum rdx_acquisition_progress_event {
    RDX_ACQUIRE_ENTER = 1,
    RDX_ACQUIRE_RETURN = 2
} rdx_acquisition_progress_event;

/* Observed native boundaries only; never an operation result or authority. */
void rdx_record_acquisition_progress(
    rdx_acquisition_stage stage, rdx_acquisition_progress_event event
);

/* Private stderr evidence only; scalar classes never affect native return status. */
typedef struct rdx_interface_error_evidence {
    uint32_t status;
    uint8_t domain;
    uint8_t code;
    uint8_t reason;
    uint8_t under_domain;
    uint8_t under_code;
} rdx_interface_error_evidence;
void rdx_record_interface_error_evidence(const rdx_interface_error_evidence *evidence);

enum {
    RDX_USB_BOT_CBW_LENGTH = 31,
    RDX_USB_BOT_CSW_LENGTH = 13
};

typedef enum rdx_usb_bot_direction {
    RDX_USB_BOT_NO_DATA = 0,
    RDX_USB_BOT_DATA_OUT = 1,
    RDX_USB_BOT_DATA_IN = 2
} rdx_usb_bot_direction;

typedef enum rdx_usb_bot_csw_status {
    RDX_USB_BOT_COMMAND_PASSED = 0,
    RDX_USB_BOT_COMMAND_FAILED = 1,
    RDX_USB_BOT_PHASE_ERROR = 2
} rdx_usb_bot_csw_status;

typedef struct rdx_scsi_command {
    uint8_t cdb[16];
    uint8_t cdb_length;
    uint8_t direction;
    uint8_t *data;
    uint32_t data_length;
} rdx_scsi_command;

bool rdx_usb_bot_build_cbw(
    const uint8_t *cdb,
    uint8_t cdb_length,
    rdx_usb_bot_direction direction,
    uint32_t transfer_length,
    uint32_t tag,
    uint8_t output[RDX_USB_BOT_CBW_LENGTH]
);
bool rdx_usb_bot_parse_csw(
    const uint8_t *bytes,
    size_t length,
    uint32_t expected_tag,
    uint32_t requested_length,
    uint32_t *transferred_length,
    rdx_usb_bot_csw_status *status
);
rdx_macos_status rdx_macos_usb_bot_acquire(
    io_service_t scsi_service,
    const rdx_macos_candidate_record *expected,
    rdx_macos_usb_bot_lease **out_lease
);
void rdx_macos_usb_bot_release(rdx_macos_usb_bot_lease *lease);
rdx_macos_status rdx_macos_usb_bot_transfer(
    rdx_macos_usb_bot_lease *lease,
    bool input,
    uint8_t *bytes,
    uint32_t length,
    uint32_t timeout_ms,
    uint32_t *transferred,
    bool *stalled
);
rdx_macos_status rdx_macos_usb_bot_clear_in_stall(
    rdx_macos_usb_bot_lease *lease
);
rdx_macos_status rdx_execute_usb_bot_command(
    rdx_macos_usb_bot_lease *lease,
    const rdx_scsi_command *command,
    uint32_t timeout_ms,
    rdx_macos_scsi_result *result
);

rdx_da_registry *rdx_da_registry_create(void);
dispatch_queue_t rdx_da_registry_queue(rdx_da_registry *registry);
void rdx_da_registry_shutdown(rdx_da_registry *registry, DASessionRef session);
DASessionRef rdx_da_session_create(void);

enum {
    RDX_FAKE_IO = 1U << 0,
    RDX_FAKE_CF = 1U << 1,
    RDX_FAKE_PLUGIN = 1U << 2,
    RDX_FAKE_INTERFACE = 1U << 3,
    RDX_FAKE_EXCLUSIVE = 1U << 4,
    RDX_FAKE_TASK = 1U << 5
};

struct rdx_macos_device {
    io_service_t service;
    rdx_macos_candidate_record expected;
    DASessionRef session;
    DADiskRef whole_disk;
    io_service_t whole_media;
    uint64_t whole_registry_entry_id;
    char whole_media_uuid[RDX_MACOS_UUID_BYTES];
    uint64_t whole_capacity_bytes;
    uint32_t whole_bsd_major;
    uint32_t whole_bsd_minor;
    bool whole_media_uuid_present;
    bool whole_media_is_whole;
    bool whole_media_ejectable;
    bool whole_media_removable;
    char whole_bsd_name[RDX_MACOS_MAX_BSD_NAME_BYTES];
    int whole_raw_fd;
    DADiskRef media_disks[RDX_MACOS_MAX_MEDIA];
    io_service_t media_services[RDX_MACOS_MAX_MEDIA];
    uint64_t media_registry_entry_ids[RDX_MACOS_MAX_MEDIA];
    char media_uuids[RDX_MACOS_MAX_MEDIA][RDX_MACOS_UUID_BYTES];
    bool media_mounted[RDX_MACOS_MAX_MEDIA];
    uint32_t media_count;
    bool whole_mounted;
    bool whole_claimed;
    bool mapping_pinned;
    rdx_da_registry *da_registry;
#if defined(RDX_MACOS_TEST_HOOKS)
    bool test_fake;
    uint32_t fake_mask;
    rdx_macos_status test_revalidate_status;
    DAReturn test_da_status;
    rdx_macos_status test_diskutil_status;
    bool test_mounted;
    uint8_t test_events[16];
    uint8_t test_event_count;
#endif
};

struct rdx_macos_scsi_lease {
    io_service_t service;
    IOCFPlugInInterface **plugin;
    SCSITaskDeviceInterface **interface;
    bool exclusive;
    rdx_macos_usb_bot_lease *usb_bot;
    rdx_macos_candidate_record expected;
#if defined(RDX_MACOS_TEST_HOOKS)
    bool test_fake;
    uint32_t fake_mask;
#endif
};

#if defined(RDX_MACOS_TEST_HOOKS)
enum {
    RDX_TEST_EVENT_REVALIDATE_MAPPING = 1,
    RDX_TEST_EVENT_CHECK_MOUNTED = 2,
    RDX_TEST_EVENT_UNMOUNT_COMPLETED = 3,
    RDX_TEST_EVENT_CREATE_PLUGIN = 4,
    RDX_TEST_EVENT_QUERY_INTERFACE = 5,
    RDX_TEST_EVENT_OBTAIN_EXCLUSIVE = 6,
    RDX_TEST_EVENT_CLAIM_COMPLETED = 7,
    RDX_TEST_EVENT_DISKUTIL_UNMOUNT_COMPLETED = 8,
    RDX_TEST_EVENT_DISKUTIL_EJECT_COMPLETED = 9,
    RDX_TEST_EVENT_EJECT_RAW_AUTHORITY_RELEASED = 10,
    RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET = 11
};
void rdx_test_record_event(rdx_macos_device *device, uint8_t event);

typedef enum rdx_test_failure_point {
    RDX_TEST_FAIL_NONE = 0,
    RDX_TEST_FAIL_RESULT_ALLOCATION = 1,
    RDX_TEST_FAIL_PLUGIN_CREATE = 2,
    RDX_TEST_FAIL_QUERY_INTERFACE = 3,
    RDX_TEST_FAIL_OBTAIN_EXCLUSIVE = 4,
    RDX_TEST_FAIL_SCSI_LEASE_ALLOCATION = 5,
    RDX_TEST_FAIL_TASK_CREATE = 6,
    RDX_TEST_FAIL_DA_SESSION_CREATE = 7,
    RDX_TEST_FAIL_DA_REGISTRY_CREATE = 8,
    RDX_TEST_FAIL_DA_CONTEXT_CREATE = 9,
    RDX_TEST_FAIL_MATCHING_DICTIONARY_CREATE = 10,
    RDX_TEST_MATCHING_SUCCESS_WITHOUT_ITERATOR = 11
} rdx_test_failure_point;

extern _Atomic uint32_t rdx_test_failure;
bool rdx_test_failure_injected(rdx_test_failure_point point);
void rdx_test_inject_failure(rdx_test_failure_point point);
bool rdx_test_exercise_da_failure_injections(void);
#define RDX_TEST_INJECTED(point) rdx_test_failure_injected(point)
#else
#define RDX_TEST_INJECTED(point) false
#endif

extern _Atomic uint64_t rdx_result_allocations;
extern _Atomic uint64_t rdx_result_frees;
extern _Atomic uint64_t rdx_io_acquisitions;
extern _Atomic uint64_t rdx_io_releases;
extern _Atomic uint64_t rdx_cf_acquisitions;
extern _Atomic uint64_t rdx_cf_releases;
extern _Atomic uint64_t rdx_plugin_acquisitions;
extern _Atomic uint64_t rdx_plugin_releases;
extern _Atomic uint64_t rdx_interface_acquisitions;
extern _Atomic uint64_t rdx_interface_releases;
extern _Atomic uint64_t rdx_exclusive_acquisitions;
extern _Atomic uint64_t rdx_exclusive_releases;
extern _Atomic uint64_t rdx_task_acquisitions;
extern _Atomic uint64_t rdx_task_releases;
extern _Atomic uint64_t rdx_device_allocations;
extern _Atomic uint64_t rdx_device_frees;
extern _Atomic uint64_t rdx_scsi_lease_allocations;
extern _Atomic uint64_t rdx_scsi_lease_frees;
extern _Atomic uint64_t rdx_da_registry_allocations;
extern _Atomic uint64_t rdx_da_registry_frees;
extern _Atomic uint64_t rdx_da_context_allocations;
extern _Atomic uint64_t rdx_da_context_frees;
extern _Atomic uint64_t rdx_da_contexts_outstanding;

void *rdx_allocate_result(size_t size, rdx_macos_result_kind kind);
rdx_macos_status rdx_status_from_io(IOReturn status, rdx_macos_status fallback);
bool rdx_candidate_record_is_valid(const rdx_macos_candidate_record *candidate);
bool rdx_is_scsi_candidate_service(io_service_t service);
bool rdx_stable_candidate_identity_matches(
    const rdx_macos_candidate_record *left,
    const rdx_macos_candidate_record *right
);
rdx_macos_status rdx_revalidate_service(
    io_service_t service,
    const rdx_macos_candidate_record *expected
);
bool rdx_fill_candidate(
    io_service_t service,
    rdx_macos_candidate_record *candidate
);
bool rdx_records_match(
    const rdx_macos_candidate_record *left,
    const rdx_macos_candidate_record *right
);
bool rdx_copy_usb_ancestor_serial(
    io_service_t service,
    char output[RDX_MACOS_MAX_TEXT_BYTES + 1]
);
rdx_macos_status rdx_find_rebound_service(
    const rdx_macos_candidate_record *expected,
    io_service_t *out_service,
    rdx_macos_candidate_record *out_observed
);
rdx_macos_status rdx_revalidate_device(rdx_macos_device *device);
rdx_macos_status rdx_revalidate_scsi_lease(rdx_macos_scsi_lease *lease);
rdx_macos_status rdx_revalidate_mapping(rdx_macos_device *device);
bool rdx_mapping_has_mounted_media(rdx_macos_device *device);
void rdx_clear_mapping(rdx_macos_device *device);
bool rdx_copy_media_authority(
    io_service_t media,
    char uuid[RDX_MACOS_UUID_BYTES],
    bool *uuid_present,
    uint32_t *bsd_major,
    uint32_t *bsd_minor
);
bool rdx_format_media_identity(
    uint64_t registry_entry_id,
    uint64_t whole_registry_entry_id,
    char output[RDX_MACOS_UUID_BYTES]
);
bool rdx_copy_whole_media_authority(
    io_service_t media,
    char uuid[RDX_MACOS_UUID_BYTES],
    bool *uuid_present,
    uint32_t *bsd_major,
    uint32_t *bsd_minor,
    uint64_t *capacity_bytes,
    bool *whole,
    bool *ejectable,
    bool *removable
);
bool rdx_fresh_whole_media_matches(rdx_macos_device *device, int descriptor);
int rdx_open_retained_whole_raw(
    rdx_macos_device *device,
    const char *bsd_name,
    uint64_t capacity,
    bool require_writable
);
bool rdx_descriptor_is_writable(int descriptor);
bool rdx_upgrade_retained_whole_raw_for_write(rdx_macos_device *device);
bool rdx_raw_fd_matches_disk(int descriptor, DADiskRef disk);
bool rdx_media_has_system_apfs_role(io_service_t media);
bool rdx_validate_mounted_fd(
    rdx_macos_device *device,
    int descriptor,
    uint64_t expected_device_id
);
bool rdx_write_gpt_layout(int descriptor, uint64_t capacity,
    uint32_t signature, uint64_t *volume_sectors);
#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_test_validate_gpt_layout(int descriptor, uint64_t capacity,
    uint32_t signature, uint64_t volume_sectors);
#endif

void rdx_track_io_acquire(void);
void rdx_release_io(io_object_t object);
void rdx_track_cf_acquire(void);
void rdx_release_cf(CFTypeRef CF_RELEASES_ARGUMENT object);
void rdx_track_plugin_acquire(void);
void rdx_release_plugin(IOCFPlugInInterface **plugin);
void rdx_track_interface_acquire(void);
void rdx_release_interface(SCSITaskDeviceInterface **interface);
void rdx_track_exclusive_acquire(void);
void rdx_track_exclusive_release(void);
void rdx_track_task_acquire(void);
void rdx_release_task(SCSITaskInterface **task);

/* Validates a synthesized APFS volume against one physical whole-media ID. */
bool rdx_apfs_volume_matches(DADiskRef disk, uint64_t expected_whole_id);
#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_macos_test_whole_disk_mapping(const char *bsd);
#endif

#endif
