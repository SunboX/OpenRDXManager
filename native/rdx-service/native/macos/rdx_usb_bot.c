// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <string.h>

#define RDX_USB_BOT_CBW_SIGNATURE UINT32_C(0x43425355)
#define RDX_USB_BOT_CSW_SIGNATURE UINT32_C(0x53425355)

static _Atomic uint32_t rdx_usb_bot_next_tag = UINT32_C(0x52445831);

static void rdx_usb_bot_put_u32(uint8_t output[4], uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static uint32_t rdx_usb_bot_get_u32(const uint8_t input[4]) {
    return (uint32_t)input[0] |
        ((uint32_t)input[1] << 8) |
        ((uint32_t)input[2] << 16) |
        ((uint32_t)input[3] << 24);
}

bool rdx_usb_bot_build_cbw(
    const uint8_t *cdb,
    uint8_t cdb_length,
    rdx_usb_bot_direction direction,
    uint32_t transfer_length,
    uint32_t tag,
    uint8_t output[RDX_USB_BOT_CBW_LENGTH]
) {
    if (cdb == NULL || output == NULL || cdb_length == 0 || cdb_length > 16 ||
        transfer_length > RDX_MACOS_MAX_TRANSFER_BYTES ||
        direction > RDX_USB_BOT_DATA_IN ||
        (transfer_length == 0) != (direction == RDX_USB_BOT_NO_DATA)) {
        return false;
    }
    memset(output, 0, RDX_USB_BOT_CBW_LENGTH);
    rdx_usb_bot_put_u32(&output[0], RDX_USB_BOT_CBW_SIGNATURE);
    rdx_usb_bot_put_u32(&output[4], tag);
    rdx_usb_bot_put_u32(&output[8], transfer_length);
    output[12] = direction == RDX_USB_BOT_DATA_IN ? 0x80U : 0;
    output[13] = 0;
    output[14] = cdb_length;
    memcpy(&output[15], cdb, cdb_length);
    return true;
}

bool rdx_usb_bot_parse_csw(
    const uint8_t *bytes,
    size_t length,
    uint32_t expected_tag,
    uint32_t requested_length,
    uint32_t *transferred_length,
    rdx_usb_bot_csw_status *status
) {
    if (bytes == NULL || transferred_length == NULL || status == NULL ||
        length != RDX_USB_BOT_CSW_LENGTH ||
        rdx_usb_bot_get_u32(&bytes[0]) != RDX_USB_BOT_CSW_SIGNATURE ||
        rdx_usb_bot_get_u32(&bytes[4]) != expected_tag) {
        return false;
    }
    uint32_t residue = rdx_usb_bot_get_u32(&bytes[8]);
    if (residue > requested_length || bytes[12] > RDX_USB_BOT_PHASE_ERROR) {
        return false;
    }
    *transferred_length = requested_length - residue;
    *status = (rdx_usb_bot_csw_status)bytes[12];
    return true;
}

/** Returns a nonzero process-wide BOT command tag. */
static uint32_t rdx_usb_bot_allocate_tag(void) {
    uint32_t tag = atomic_fetch_add_explicit(
        &rdx_usb_bot_next_tag,
        1,
        memory_order_relaxed
    );
    if (tag == 0) {
        tag = atomic_fetch_add_explicit(
            &rdx_usb_bot_next_tag,
            1,
            memory_order_relaxed
        );
    }
    return tag;
}

/** Executes the three BOT phases and validates their exact byte accounting. */
static rdx_macos_status rdx_usb_bot_run(
    rdx_macos_usb_bot_lease *lease,
    const rdx_scsi_command *command,
    uint32_t timeout_ms,
    uint32_t *realized,
    rdx_usb_bot_csw_status *command_status,
    uint8_t *attempted
) {
    uint32_t tag = rdx_usb_bot_allocate_tag();
    uint8_t cbw[RDX_USB_BOT_CBW_LENGTH] = {0};
    rdx_usb_bot_direction direction = (rdx_usb_bot_direction)command->direction;
    if (!rdx_usb_bot_build_cbw(
            command->cdb,
            command->cdb_length,
            direction,
            command->data_length,
            tag,
            cbw
        )) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    uint32_t transferred = 0;
    bool stalled = false;
    *attempted = 1;
    rdx_macos_status status = rdx_macos_usb_bot_transfer(
        lease,
        false,
        cbw,
        sizeof(cbw),
        timeout_ms,
        &transferred,
        &stalled
    );
    if (status != RDX_MACOS_STATUS_OK || stalled || transferred != sizeof(cbw)) {
        return status == RDX_MACOS_STATUS_OK ? RDX_MACOS_STATUS_NATIVE_FAILURE : status;
    }
    uint32_t data_transferred = 0;
    if (command->data_length > 0) {
        status = rdx_macos_usb_bot_transfer(
            lease,
            direction == RDX_USB_BOT_DATA_IN,
            command->data,
            command->data_length,
            timeout_ms,
            &data_transferred,
            &stalled
        );
        if (status != RDX_MACOS_STATUS_OK || stalled ||
            (direction == RDX_USB_BOT_DATA_OUT &&
                data_transferred != command->data_length)) {
            return status == RDX_MACOS_STATUS_OK
                ? RDX_MACOS_STATUS_NATIVE_FAILURE
                : status;
        }
    }
    uint8_t csw[RDX_USB_BOT_CSW_LENGTH] = {0};
    transferred = 0;
    status = rdx_macos_usb_bot_transfer(
        lease,
        true,
        csw,
        sizeof(csw),
        timeout_ms,
        &transferred,
        &stalled
    );
    if (status != RDX_MACOS_STATUS_OK && stalled) {
        status = rdx_macos_usb_bot_clear_in_stall(lease);
        if (status == RDX_MACOS_STATUS_OK) {
            stalled = false;
            transferred = 0;
            status = rdx_macos_usb_bot_transfer(
                lease,
                true,
                csw,
                sizeof(csw),
                timeout_ms,
                &transferred,
                &stalled
            );
        }
    }
    if (status != RDX_MACOS_STATUS_OK || stalled || transferred != sizeof(csw) ||
        !rdx_usb_bot_parse_csw(
            csw,
            sizeof(csw),
            tag,
            command->data_length,
            realized,
            command_status
        ) ||
        *command_status == RDX_USB_BOT_PHASE_ERROR ||
        *realized != data_transferred) {
        return status == RDX_MACOS_STATUS_OK ? RDX_MACOS_STATUS_NATIVE_FAILURE : status;
    }
    return RDX_MACOS_STATUS_OK;
}

/** Requests bounded sense bytes after one device-reported command failure. */
static void rdx_usb_bot_request_sense(
    rdx_macos_usb_bot_lease *lease,
    uint32_t timeout_ms,
    rdx_macos_scsi_result *result
) {
    rdx_scsi_command sense = {0};
    sense.cdb[0] = 0x03;
    sense.cdb[4] = RDX_MACOS_MAX_SENSE_BYTES;
    sense.cdb_length = 6;
    sense.direction = RDX_USB_BOT_DATA_IN;
    sense.data = result->sense;
    sense.data_length = RDX_MACOS_MAX_SENSE_BYTES;
    uint32_t realized = 0;
    rdx_usb_bot_csw_status command_status = RDX_USB_BOT_PHASE_ERROR;
    uint8_t attempted = 0;
    if (rdx_usb_bot_run(
            lease,
            &sense,
            timeout_ms,
            &realized,
            &command_status,
            &attempted
        ) == RDX_MACOS_STATUS_OK &&
        command_status == RDX_USB_BOT_COMMAND_PASSED && attempted == 1 &&
        realized <= RDX_MACOS_MAX_SENSE_BYTES) {
        result->sense_length = realized;
    }
}

/** Executes one semantic SCSI command through the captured USB BOT transport. */
rdx_macos_status rdx_execute_usb_bot_command(
    rdx_macos_usb_bot_lease *lease,
    const rdx_scsi_command *command,
    uint32_t timeout_ms,
    rdx_macos_scsi_result *result
) {
    if (lease == NULL || command == NULL || result == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    uint32_t realized = 0;
    rdx_usb_bot_csw_status command_status = RDX_USB_BOT_PHASE_ERROR;
    rdx_macos_status status = rdx_usb_bot_run(
        lease,
        command,
        timeout_ms,
        &realized,
        &command_status,
        &result->attempted
    );
    if (status != RDX_MACOS_STATUS_OK) {
        return status;
    }
    result->service_response = kSCSIServiceResponse_TASK_COMPLETE;
    result->realized_transfer_count = realized;
    if (command->direction == RDX_USB_BOT_DATA_IN) {
        result->data_length = realized;
    }
    if (command_status == RDX_USB_BOT_COMMAND_PASSED) {
        result->scsi_status = kSCSITaskStatus_GOOD;
        return RDX_MACOS_STATUS_OK;
    }
    result->scsi_status = kSCSITaskStatus_CHECK_CONDITION;
    rdx_usb_bot_request_sense(lease, timeout_ms, result);
    return RDX_MACOS_STATUS_OK;
}
