// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <string.h>

#include "rdx_serial_contract.inc"
#include "rdx_manufacturing_contract.inc"

_Static_assert(sizeof(SCSI_Sense_Data) <= RDX_MACOS_MAX_SENSE_BYTES,
               "Apple request sense must fit the bounded ABI buffer");

static void rdx_encode_u24(uint32_t value, uint8_t output[3]) {
    output[0] = (uint8_t)((value >> 16) & 0xFFU);
    output[1] = (uint8_t)((value >> 8) & 0xFFU);
    output[2] = (uint8_t)(value & 0xFFU);
}

static bool rdx_mode_select_is_valid(const uint8_t *data, uint32_t length) {
    if (data == NULL || length < 10 || length > RDX_MACOS_MAX_TRANSFER_BYTES ||
        data[0] != 0 || data[1] != 0 || data[2] != 0) {
        return false;
    }
    uint32_t descriptor_length = ((uint32_t)data[6] << 8) | data[7];
    uint32_t page_offset = 8U + descriptor_length;
    if (page_offset + 2U > length || (data[page_offset] & 0x40U) != 0) {
        return false;
    }
    uint8_t page = data[page_offset] & 0x3FU;
    uint8_t body_length = data[page_offset + 1U];
    uint8_t minimum = 0;
    if (page == 0x31U) {
        minimum = 3;
    } else if (page == 0x33U) {
        minimum = 2;
    } else if (page == 0x34U) {
        minimum = 5;
    } else {
        return false;
    }
    return body_length >= minimum && page_offset + 2U + body_length == length;
}

/** Independently restricts compatibility authorization to its serial-derived framing. */
static bool rdx_compatibility_authorization_is_valid(const uint8_t *data, uint32_t length) {
    static const uint8_t key[8] = {0x55, 0xaa, 0x25, 0x46, 0x04, 0xc1, 0x1d, 0xb7};
    if (data == NULL || length != 10 || data[0] != 0 || data[1] != 0) { return false; }
    for (size_t index = 0; index < 8; index++) {
        uint8_t decoded = data[index + 2] ^ key[index];
        if (decoded < 0x20 || decoded > 0x7e) { return false; }
    }
    return true;
}

static bool rdx_request_is_valid(const rdx_macos_scsi_request *request) {
    if (request == NULL || request->abi_version != RDX_MACOS_ABI_VERSION ||
        request->timeout_ms == 0 || request->timeout_ms > 300000U ||
        request->data_length > RDX_MACOS_MAX_TRANSFER_BYTES ||
        request->offset > 0x00FFFFFFU || request->save_pages > 1 ||
        request->reserved[0] != 0 || request->reserved[1] != 0 ||
        request->reserved[2] != 0) {
        return false;
    }
    switch (request->operation) {
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_SECTOR_CHUNK:
            return request->offset < 32 && request->data_length == 0 && request->save_pages == 0;
        case RDX_MACOS_OPERATION_OPENRDX_SERIAL_CAPABILITY:
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RESTORE_CAPABILITY:
        case RDX_MACOS_OPERATION_OPENRDX_MECHANISM_DIAGNOSTICS:
            return request->offset == 0 && request->data_length == 0 && request->save_pages == 0;
        case RDX_MACOS_OPERATION_OPENRDX_SET_SERIAL:
            return request->offset == 0 && request->save_pages == 0 &&
                rdx_serial_payload_is_valid(request->data, request->data_length);
        case RDX_MACOS_OPERATION_OPENRDX_RESTORE_MANUFACTURING:
            return request->offset == 0 && request->save_pages == 0 &&
                rdx_manufacturing_restore_payload_is_valid(request->data, request->data_length);
        case RDX_MACOS_OPERATION_COMPATIBILITY_RECEIVER_AUTHORIZATION:
            return request->offset == 0 && request->save_pages == 0 &&
                rdx_compatibility_authorization_is_valid(request->data, request->data_length);
        case RDX_MACOS_OPERATION_COMPATIBILITY_RECEIVER_HEADER_SETUP:
            return request->offset == 0 && request->save_pages == 0 && request->data_length == 0;
        case RDX_MACOS_OPERATION_MODE_SELECT:
            return request->offset == 0 &&
                rdx_mode_select_is_valid(request->data, request->data_length);
        case RDX_MACOS_OPERATION_FIRMWARE_CHUNK:
            return request->data_length > 0 && request->save_pages == 0;
        case RDX_MACOS_OPERATION_FIRMWARE_FINALIZE:
            return request->data_length == 0 && request->save_pages == 0;
        case RDX_MACOS_OPERATION_SELF_TEST:
        case RDX_MACOS_OPERATION_LED_ON:
        case RDX_MACOS_OPERATION_LED_OFF:
        case RDX_MACOS_OPERATION_UNIT_RESET:
        case RDX_MACOS_OPERATION_EJECT_MEDIA:
        case RDX_MACOS_OPERATION_INQUIRY_STANDARD:
        case RDX_MACOS_OPERATION_VENDOR_0283_FACTORY_INFO:
        case RDX_MACOS_OPERATION_VENDOR_0283_USB_IDENTITY:
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_FIRST:
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_SECOND:
        case RDX_MACOS_OPERATION_OPENRDX_OPERATIONAL_STATE_RECORD:
        case RDX_MACOS_OPERATION_INQUIRY_DEVICE_IDENTIFICATION:
        case RDX_MACOS_OPERATION_INQUIRY_MEDIA_IDENTIFICATION:
        case RDX_MACOS_OPERATION_INQUIRY_MEDIA_DEVICE:
        case RDX_MACOS_OPERATION_LOG_SENSE_TEMPERATURE:
        case RDX_MACOS_OPERATION_LOG_SENSE_DRIVE:
        case RDX_MACOS_OPERATION_LOG_SENSE_CARTRIDGE:
        case RDX_MACOS_OPERATION_MODE_SENSE_CAPABILITIES:
        case RDX_MACOS_OPERATION_MODE_SENSE_DRIVE:
        case RDX_MACOS_OPERATION_MODE_SENSE_SATA:
        case RDX_MACOS_OPERATION_SECURITY_IN_0010:
        case RDX_MACOS_OPERATION_SECURITY_IN_0020:
        case RDX_MACOS_OPERATION_SECURITY_IN_0021:
            return request->data_length == 0 && request->offset == 0 &&
                request->save_pages == 0;
        default:
            return false;
    }
}

static void rdx_set_six_byte_command(
    rdx_scsi_command *command,
    uint8_t opcode,
    uint8_t byte_one,
    uint8_t allocation
) {
    command->cdb[0] = opcode;
    command->cdb[1] = byte_one;
    command->cdb[4] = allocation;
    command->cdb_length = 6;
}

static void rdx_set_ten_byte_page_command(
    rdx_scsi_command *command,
    uint8_t opcode,
    uint8_t page
) {
    command->cdb[0] = opcode;
    command->cdb[2] = page;
    command->cdb[8] = 0xFE;
    command->cdb_length = 10;
}

static void rdx_set_security_command(rdx_scsi_command *command, uint16_t selector) {
    command->cdb[0] = 0xA2;
    command->cdb[1] = 0x20;
    command->cdb[2] = (uint8_t)(selector >> 8);
    command->cdb[3] = (uint8_t)(selector & 0xFFU);
    command->cdb[8] = 0x10;
    command->cdb_length = 12;
}

static bool rdx_build_scsi_command(
    const rdx_macos_scsi_request *request,
    rdx_macos_scsi_result *result,
    rdx_scsi_command *command
) {
    memset(command, 0, sizeof(*command));
    switch (request->operation) {
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RESTORE_CAPABILITY:
        case RDX_MACOS_OPERATION_OPENRDX_RESTORE_MANUFACTURING: {
            bool probe = request->operation == RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RESTORE_CAPABILITY;
            static const uint8_t capability[10] = {0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0};
            static const uint8_t write[10] = {0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0};
            memcpy(command->cdb, probe ? capability : write, 10);
            command->cdb_length = 10;
            command->direction = probe ? kSCSIDataTransfer_NoDataTransfer : kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = probe ? NULL : (uint8_t *)request->data;
            command->data_length = probe ? 0 : 528;
            return true;
        }
        case RDX_MACOS_OPERATION_OPENRDX_MECHANISM_DIAGNOSTICS:
            command->cdb[0] = 0xe8;
            command->cdb[5] = 128;
            command->cdb_length = 6;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 128;
            return true;
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_SECTOR_CHUNK: {
            /* The semantic field is an index, independently bounded before construction. */
            if (request->offset >= 32) { return false; }
            uint32_t address = 0x3e000U + request->offset * 128U;
            command->cdb[0] = 0xe7;
            command->cdb[2] = (uint8_t)(address >> 16);
            command->cdb[3] = (uint8_t)(address >> 8);
            command->cdb[4] = (uint8_t)address;
            command->cdb[5] = 128;
            command->cdb_length = 6;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 128;
            return true;
        }
        case RDX_MACOS_OPERATION_OPENRDX_SERIAL_CAPABILITY:
        case RDX_MACOS_OPERATION_OPENRDX_SET_SERIAL: {
            bool probe = request->operation == RDX_MACOS_OPERATION_OPENRDX_SERIAL_CAPABILITY;
            static const uint8_t capability[10] = {0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0};
            static const uint8_t write[10] = {0x3b, 2, 0x53, 0, 0, 0, 0, 1, 0x18, 0};
            memcpy(command->cdb, probe ? capability : write, 10);
            command->cdb_length = 10;
            command->direction = probe ? kSCSIDataTransfer_NoDataTransfer : kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = probe ? NULL : (uint8_t *)request->data;
            command->data_length = probe ? 0 : 280;
            return true;
        }
        case RDX_MACOS_OPERATION_COMPATIBILITY_RECEIVER_AUTHORIZATION: {
            static const uint8_t cdb[10] = {0x3b, 2, 0x80, 0, 0, 0, 0, 0, 10, 0};
            memcpy(command->cdb, cdb, sizeof(cdb));
            command->cdb_length = 10;
            command->direction = kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = (uint8_t *)request->data;
            command->data_length = 10;
            return true;
        }
        case RDX_MACOS_OPERATION_COMPATIBILITY_RECEIVER_HEADER_SETUP: {
            /* Public OpenRDX updater: the only admitted header location/value. */
            static const uint8_t cdb[10] = {0x3b, 2, 0x82, 2, 0x0f, 0xf8, 0, 0, 2, 0};
            memcpy(command->cdb, cdb, sizeof(cdb));
            result->data[0] = 0;
            result->data[1] = 0;
            command->cdb_length = 10;
            command->direction = kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = result->data;
            command->data_length = 2;
            return true;
        }
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_FIRST:
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_SECOND:
        case RDX_MACOS_OPERATION_OPENRDX_OPERATIONAL_STATE_RECORD: {
            /* scsi.c TI_READ_FLASH uses CDB[1..4] BE32 and one-byte CDB[5]
             * length. Only these complete manufacturing/state ranges exist. */
            bool state = request->operation == RDX_MACOS_OPERATION_OPENRDX_OPERATIONAL_STATE_RECORD;
            command->cdb[0] = 0xe7;
            command->cdb[2] = 3;
            command->cdb[3] = state ? 0xf0 : 0xe0;
            command->cdb[4] = request->operation == RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_SECOND ? 0x80 : 0;
            command->cdb[5] = state ? 0x40 : 0x80;
            command->cdb_length = 6;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = command->cdb[5];
            return true;
        }
        case RDX_MACOS_OPERATION_VENDOR_0283_FACTORY_INFO:
        case RDX_MACOS_OPERATION_VENDOR_0283_USB_IDENTITY:
            command->cdb[0] = 0x3C;
            command->cdb[1] = 0x02;
            command->cdb[2] =
                request->operation == RDX_MACOS_OPERATION_VENDOR_0283_FACTORY_INFO
                    ? 2 : 10;
            command->cdb[8] =
                request->operation == RDX_MACOS_OPERATION_VENDOR_0283_FACTORY_INFO
                    ? 0xAC : 0x20;
            command->cdb_length = 10;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = command->cdb[8];
            return true;
        case RDX_MACOS_OPERATION_SELF_TEST:
            rdx_set_six_byte_command(command, 0x1D, 0x04, 0);
            command->direction = kSCSIDataTransfer_NoDataTransfer;
            return true;
        case RDX_MACOS_OPERATION_LED_ON:
        case RDX_MACOS_OPERATION_LED_OFF: {
            rdx_set_six_byte_command(command, 0x1D, 0, 8);
            uint32_t value = request->operation == RDX_MACOS_OPERATION_LED_ON ? 0U : 1U;
            result->data[0] = 0x80;
            result->data[3] = 4;
            result->data[4] = (uint8_t)(value >> 24);
            result->data[5] = (uint8_t)(value >> 16);
            result->data[6] = (uint8_t)(value >> 8);
            result->data[7] = (uint8_t)value;
            command->direction = kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = result->data;
            command->data_length = 8;
            return true;
        }
        case RDX_MACOS_OPERATION_UNIT_RESET:
            rdx_set_six_byte_command(command, 0x1D, 0x05, 0);
            command->direction = kSCSIDataTransfer_NoDataTransfer;
            return true;
        case RDX_MACOS_OPERATION_EJECT_MEDIA:
            rdx_set_six_byte_command(command, 0x1B, 0, 0);
            command->cdb[4] = 0x02;
            command->direction = kSCSIDataTransfer_NoDataTransfer;
            return true;
        case RDX_MACOS_OPERATION_INQUIRY_STANDARD:
            rdx_set_six_byte_command(command, 0x12, 0, 0xFE);
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0xFE;
            return true;
        case RDX_MACOS_OPERATION_INQUIRY_DEVICE_IDENTIFICATION:
            rdx_set_six_byte_command(command, 0x12, 1, 0xFE);
            command->cdb[2] = 0x83;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0xFE;
            return true;
        case RDX_MACOS_OPERATION_INQUIRY_MEDIA_IDENTIFICATION:
            rdx_set_six_byte_command(command, 0x12, 1, 0xFE);
            command->cdb[2] = 0xC0;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0xFE;
            return true;
        case RDX_MACOS_OPERATION_INQUIRY_MEDIA_DEVICE:
            rdx_set_six_byte_command(command, 0x12, 1, 0);
            command->cdb[2] = 0xC2;
            command->cdb[3] = 0x02;
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0x200;
            return true;
        case RDX_MACOS_OPERATION_LOG_SENSE_TEMPERATURE:
            rdx_set_ten_byte_page_command(command, 0x4D, 0x0D);
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0xFE;
            return true;
        case RDX_MACOS_OPERATION_LOG_SENSE_DRIVE:
        case RDX_MACOS_OPERATION_LOG_SENSE_CARTRIDGE:
            rdx_set_ten_byte_page_command(
                command,
                0x4D,
                request->operation == RDX_MACOS_OPERATION_LOG_SENSE_DRIVE ? 0x20 : 0x21
            );
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0xFE;
            return true;
        case RDX_MACOS_OPERATION_MODE_SENSE_CAPABILITIES:
        case RDX_MACOS_OPERATION_MODE_SENSE_DRIVE:
        case RDX_MACOS_OPERATION_MODE_SENSE_SATA: {
            uint8_t page = 0x31;
            if (request->operation == RDX_MACOS_OPERATION_MODE_SENSE_DRIVE) {
                page = 0x33;
            } else if (request->operation == RDX_MACOS_OPERATION_MODE_SENSE_SATA) {
                page = 0x34;
            }
            rdx_set_ten_byte_page_command(command, 0x5A, page);
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = 0xFE;
            return true;
        }
        case RDX_MACOS_OPERATION_SECURITY_IN_0010:
        case RDX_MACOS_OPERATION_SECURITY_IN_0020:
        case RDX_MACOS_OPERATION_SECURITY_IN_0021: {
            uint16_t selector = 0x0010;
            if (request->operation == RDX_MACOS_OPERATION_SECURITY_IN_0020) {
                selector = 0x0020;
            } else if (request->operation == RDX_MACOS_OPERATION_SECURITY_IN_0021) {
                selector = 0x0021;
            }
            rdx_set_security_command(command, selector);
            command->direction = kSCSIDataTransfer_FromTargetToInitiator;
            command->data = result->data;
            command->data_length = RDX_MACOS_MAX_TRANSFER_BYTES;
            return true;
        }
        case RDX_MACOS_OPERATION_MODE_SELECT: {
            uint16_t length = (uint16_t)request->data_length;
            command->cdb[0] = 0x55;
            command->cdb[1] = (uint8_t)(0x10U | request->save_pages);
            command->cdb[7] = (uint8_t)(length >> 8);
            command->cdb[8] = (uint8_t)length;
            command->cdb_length = 10;
            command->direction = kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = (uint8_t *)request->data;
            command->data_length = request->data_length;
            return true;
        }
        case RDX_MACOS_OPERATION_FIRMWARE_CHUNK: {
            uint8_t offset[3];
            uint8_t length[3];
            rdx_encode_u24(request->offset, offset);
            rdx_encode_u24(request->data_length, length);
            command->cdb[0] = 0x3B;
            command->cdb[1] = 0x04;
            memcpy(&command->cdb[3], offset, sizeof(offset));
            memcpy(&command->cdb[6], length, sizeof(length));
            command->cdb_length = 10;
            command->direction = kSCSIDataTransfer_FromInitiatorToTarget;
            command->data = (uint8_t *)request->data;
            command->data_length = request->data_length;
            return true;
        }
        case RDX_MACOS_OPERATION_FIRMWARE_FINALIZE: {
            uint8_t offset[3];
            rdx_encode_u24(request->offset, offset);
            command->cdb[0] = 0x3B;
            command->cdb[1] = 0x05;
            memcpy(&command->cdb[3], offset, sizeof(offset));
            command->cdb_length = 10;
            command->direction = kSCSIDataTransfer_NoDataTransfer;
            return true;
        }
        default:
            return false;
    }
}

static rdx_macos_status rdx_setup_task(
    SCSITaskInterface **task,
    const rdx_macos_scsi_request *request,
    const rdx_scsi_command *command,
    SCSITaskSGElement *element
) {
    IOReturn status = (*task)->SetTaskAttribute(task, kSCSITask_SIMPLE);
    if (status != kIOReturnSuccess) {
        return rdx_status_from_io(status, RDX_MACOS_STATUS_NATIVE_FAILURE);
    }
    status = (*task)->SetCommandDescriptorBlock(
        task,
        (uint8_t *)command->cdb,
        command->cdb_length
    );
    if (status != kIOReturnSuccess) {
        return rdx_status_from_io(status, RDX_MACOS_STATUS_NATIVE_FAILURE);
    }
    if (command->data_length == 0) {
        status = (*task)->SetScatterGatherEntries(
            task,
            NULL,
            0,
            0,
            kSCSIDataTransfer_NoDataTransfer
        );
    } else {
        *element = (SCSITaskSGElement){
            .address = (IOVirtualAddress)(uintptr_t)command->data,
            .length = command->data_length
        };
        status = (*task)->SetScatterGatherEntries(
            task,
            element,
            1,
            command->data_length,
            command->direction
        );
    }
    if (status != kIOReturnSuccess) {
        return rdx_status_from_io(status, RDX_MACOS_STATUS_NATIVE_FAILURE);
    }
    status = (*task)->SetTimeoutDuration(task, request->timeout_ms);
    if (status != kIOReturnSuccess) {
        return rdx_status_from_io(status, RDX_MACOS_STATUS_NATIVE_FAILURE);
    }
    return RDX_MACOS_STATUS_OK;
}

static SCSITaskInterface **rdx_create_scsi_task(
    rdx_macos_scsi_lease *lease
) {
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_TASK_CREATE)) {
        return NULL;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (lease->test_fake) {
        return NULL;
    }
#endif
    return (*lease->interface)->CreateSCSITask(lease->interface);
}

/** TI_READ_FLASH has BOT direction fallback but is absent from UAS direction dispatch. */
static bool rdx_scsi_transport_is_valid(
    const rdx_macos_scsi_lease *lease, const rdx_macos_scsi_request *request
) {
    switch (request->operation) {
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_FIRST:
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_RECORD_SECOND:
        case RDX_MACOS_OPERATION_OPENRDX_OPERATIONAL_STATE_RECORD:
        case RDX_MACOS_OPERATION_OPENRDX_MANUFACTURING_SECTOR_CHUNK:
        case RDX_MACOS_OPERATION_OPENRDX_MECHANISM_DIAGNOSTICS:
            /* A non-null owner was admitted only after exact interface 08/06/50
             * and bulk-pipe descriptor validation in rdx_usb_host.m. */
            return lease->usb_bot != NULL;
        default:
            return true;
    }
}

rdx_macos_status rdx_macos_execute_scsi(
    rdx_macos_scsi_lease *lease,
    const rdx_macos_scsi_request *request,
    rdx_macos_scsi_result **out_result
) {
    if (out_result == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    if (lease == NULL || !rdx_request_is_valid(request)) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    if (!rdx_scsi_transport_is_valid(lease, request)) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    rdx_macos_scsi_result *result = rdx_allocate_result(
        sizeof(*result),
        RDX_MACOS_RESULT_SCSI
    );
    if (result == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    rdx_macos_status status = rdx_revalidate_scsi_lease(lease);
    SCSITaskInterface **task = NULL;
    rdx_scsi_command command;
    SCSITaskSGElement element = {0};
    if (status != RDX_MACOS_STATUS_OK ||
        !rdx_build_scsi_command(request, result, &command)) {
        if (status == RDX_MACOS_STATUS_OK) {
            status = RDX_MACOS_STATUS_INVALID_ARGUMENT;
        }
        goto cleanup;
    }
    if (lease->usb_bot != NULL) {
        status = rdx_execute_usb_bot_command(
            lease->usb_bot,
            &command,
            request->timeout_ms,
            result
        );
        goto cleanup;
    }
    task = rdx_create_scsi_task(lease);
    if (task == NULL) {
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        goto cleanup;
    }
    rdx_track_task_acquire();
    /* Keep the SG element alive until synchronous execution has returned. */
    status = rdx_setup_task(task, request, &command, &element);
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }

    SCSITaskStatus scsi_status = kSCSITaskStatus_No_Status;
    UInt64 realized_transfer = 0;
    result->attempted = 1;
    IOReturn io_status = (*task)->ExecuteTaskSync(
        task,
        (SCSI_Sense_Data *)result->sense,
        &scsi_status,
        &realized_transfer
    );
    if (io_status != kIOReturnSuccess) {
        status = rdx_status_from_io(io_status, RDX_MACOS_STATUS_NATIVE_FAILURE);
        goto cleanup;
    }
    SCSIServiceResponse service_response =
        kSCSIServiceResponse_SERVICE_DELIVERY_OR_TARGET_FAILURE;
    io_status = (*task)->GetSCSIServiceResponse(task, &service_response);
    if (io_status != kIOReturnSuccess || realized_transfer > command.data_length) {
        status = rdx_status_from_io(io_status, RDX_MACOS_STATUS_NATIVE_FAILURE);
        if (io_status == kIOReturnSuccess) {
            status = RDX_MACOS_STATUS_NATIVE_FAILURE;
        }
        goto cleanup;
    }
    result->scsi_status = (uint8_t)scsi_status;
    result->service_response = (uint8_t)service_response;
    result->realized_transfer_count = realized_transfer;
    if (command.direction == kSCSIDataTransfer_FromTargetToInitiator) {
        result->data_length = (uint32_t)realized_transfer;
    }
    if (scsi_status == kSCSITaskStatus_CHECK_CONDITION) {
        result->sense_length = sizeof(SCSI_Sense_Data);
    }
    status = RDX_MACOS_STATUS_OK;

cleanup:
    rdx_release_task(task);
    result->header.status = status;
    *out_result = result;
    return status;
}

#if defined(RDX_MACOS_TEST_HOOKS)
#include "rdx_serial_tests.inc"
/** Proves fixed E7 ranges and BOT-only admission using local records without native I/O. */
bool rdx_macos_test_openrdx_record_scsi_contract(void) {
    const uint8_t expected[3][6] = {
        {0xe7, 0, 3, 0xe0, 0, 0x80},
        {0xe7, 0, 3, 0xe0, 0x80, 0x80},
        {0xe7, 0, 3, 0xf0, 0, 0x40}
    };
    for (uint32_t index = 0; index < 3; index++) {
        rdx_macos_scsi_request request = {
            .abi_version = RDX_MACOS_ABI_VERSION,
            .operation = 26 + index,
            .timeout_ms = 30000
        };
        rdx_macos_scsi_result result = {0};
        rdx_scsi_command command = {0};
        rdx_macos_scsi_lease lease = {0};
        rdx_macos_scsi_result *rejected = NULL;
        if (!rdx_request_is_valid(&request) ||
            !rdx_build_scsi_command(&request, &result, &command) ||
            command.cdb_length != 6 || memcmp(command.cdb, expected[index], 6) != 0 ||
            command.direction != kSCSIDataTransfer_FromTargetToInitiator ||
            command.data != result.data || command.data_length != expected[index][5] ||
            rdx_scsi_transport_is_valid(&lease, &request)) {
            return false;
        }
        if (rdx_macos_execute_scsi(&lease, &request, &rejected) !=
                RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE || rejected != NULL) {
            return false;
        }
        /* This address is only a non-null marker: the pure guard never dereferences it. */
        lease.usb_bot = (rdx_macos_usb_bot_lease *)(void *)&request;
        if (!rdx_scsi_transport_is_valid(&lease, &request)) { return false; }
        request.offset = 1;
        if (rdx_request_is_valid(&request)) { return false; }
        request.offset = 0; request.data_length = 1;
        if (rdx_request_is_valid(&request)) { return false; }
        request.data_length = 0; request.save_pages = 1;
        if (rdx_request_is_valid(&request)) { return false; }
    }
    rdx_macos_scsi_request unknown = {
        .abi_version = RDX_MACOS_ABI_VERSION, .operation = 35, .timeout_ms = 30000
    };
    return !rdx_request_is_valid(&unknown);
}

/** Exercises fixed compatibility setup requests, including hostile field rejection. */
bool rdx_macos_test_compatibility_setup_scsi_contract(void) {
    const uint8_t authorization[10] = {0, 0, 0x67, 0x99, 0x11, 0x73, 0x32, 0xf6, 0x25, 0x8e};
    const uint8_t expected[2][10] = {
        {0x3b, 2, 0x80, 0, 0, 0, 0, 0, 10, 0},
        {0x3b, 2, 0x82, 2, 0x0f, 0xf8, 0, 0, 2, 0}
    };
    for (size_t index = 0; index < 2; index++) {
        rdx_macos_scsi_request request = {.abi_version = RDX_MACOS_ABI_VERSION,
            .operation = (uint32_t)(24 + index), .timeout_ms = 15000,
            .data_length = index == 0 ? 10 : 0};
        if (index == 0) { memcpy(request.data, authorization, 10); }
        rdx_macos_scsi_result result;
        memset(&result, 0xa5, sizeof(result));
        rdx_scsi_command command;
        if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
            command.cdb_length != 10 || memcmp(command.cdb, expected[index], 10) != 0 ||
            command.direction != kSCSIDataTransfer_FromInitiatorToTarget ||
            command.data_length != (index == 0 ? 10U : 2U) ||
            memcmp(command.data, index == 0 ? authorization : (const uint8_t[]){0, 0}, command.data_length) != 0) {
            return false;
        }
        request.offset = 1;
        if (rdx_request_is_valid(&request)) { return false; }
        request.offset = 0; request.save_pages = 1;
        if (rdx_request_is_valid(&request)) { return false; }
        request.save_pages = 0; request.data_length = index == 0 ? 9 : 1;
        if (rdx_request_is_valid(&request)) { return false; }
        if (index == 0) {
            request.data_length = 10; request.data[0] = 1;
            if (rdx_request_is_valid(&request)) { return false; }
            request.data[0] = 0; request.data[2] = 0x55 ^ 0x1f;
            if (rdx_request_is_valid(&request)) { return false; }
        }
    }
    return true;
}

/** Proves both read families at the final C boundary, including field rejection. */
bool rdx_macos_test_factory_snapshot_scsi_contract(void) {
    const uint32_t operations[2] = {22, 23};
    const uint8_t ids[2] = {2, 10};
    const uint8_t lengths[2] = {0xAC, 0x20};
    for (size_t index = 0; index < 2; ++index) {
        rdx_macos_scsi_request request = {
            .abi_version = RDX_MACOS_ABI_VERSION,
            .operation = operations[index],
            .timeout_ms = 30000U
        };
        rdx_macos_scsi_result result = {0};
        rdx_scsi_command command = {0};
        const uint8_t expected[10] = {
            0x3C, 2, ids[index], 0, 0, 0, 0, 0, lengths[index], 0
        };
        if (!rdx_request_is_valid(&request) ||
            !rdx_build_scsi_command(&request, &result, &command) ||
            command.cdb_length != 10 ||
            memcmp(command.cdb, expected, 10) != 0 ||
            command.direction != kSCSIDataTransfer_FromTargetToInitiator ||
            command.data != result.data || command.data_length != lengths[index]) {
            return false;
        }
        request.offset = 1;
        if (rdx_request_is_valid(&request)) {
            return false;
        }
        request.offset = 0;
        request.data_length = 1;
        if (rdx_request_is_valid(&request)) {
            return false;
        }
        request.data_length = 0;
        request.save_pages = 1;
        if (rdx_request_is_valid(&request)) {
            return false;
        }
    }
    return true;
}

bool rdx_macos_test_eject_scsi_contract(void) {
    rdx_macos_scsi_request request = {
        .abi_version = RDX_MACOS_ABI_VERSION,
        .operation = RDX_MACOS_OPERATION_EJECT_MEDIA,
        .timeout_ms = 30000U
    };
    rdx_macos_scsi_result result = {0};
    rdx_scsi_command command = {0};
    static const uint8_t expected[6] = {0x1B, 0, 0, 0, 0x02, 0};
    return rdx_request_is_valid(&request) &&
        rdx_build_scsi_command(&request, &result, &command) &&
        command.cdb_length == sizeof(expected) &&
        memcmp(command.cdb, expected, sizeof(expected)) == 0 &&
        command.direction == kSCSIDataTransfer_NoDataTransfer &&
        command.data == NULL && command.data_length == 0;
}
#endif
