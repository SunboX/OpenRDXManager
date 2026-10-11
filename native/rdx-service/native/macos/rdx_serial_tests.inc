// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Checks exact serial wire commands, all sector indices, and hostile fields without I/O. */
bool rdx_macos_test_serial_contract(void) {
    rdx_macos_scsi_request request = {
        .abi_version = RDX_MACOS_ABI_VERSION, .operation = 29, .timeout_ms = 30000
    };
    rdx_macos_scsi_result result = {0};
    rdx_scsi_command command = {0};
    rdx_macos_scsi_lease lease = {0};
    for (uint32_t index = 0; index < 32; index++) {
        request.offset = index;
        const uint8_t expected[6] = {0xe7, 0, 3, (uint8_t)(0xe0 + index / 2), (uint8_t)((index % 2) * 128), 128};
        if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
            command.cdb_length != 6 || memcmp(command.cdb, expected, 6) != 0 ||
            command.data_length != 128 || command.direction != kSCSIDataTransfer_FromTargetToInitiator ||
            rdx_scsi_transport_is_valid(&lease, &request)) { return false; }
    }
    request.operation = 32; request.offset = 0;
    const uint8_t mechanism[6] = {0xe8, 0, 0, 0, 0, 128};
    if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
        memcmp(command.cdb, mechanism, 6) != 0 || command.cdb_length != 6 || command.data_length != 128 ||
        command.direction != kSCSIDataTransfer_FromTargetToInitiator || rdx_scsi_transport_is_valid(&lease, &request)) { return false; }
    request.offset = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.offset = 0; request.data_length = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.data_length = 0; request.save_pages = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.save_pages = 0; request.operation = 29;
    request.offset = 32;
    if (rdx_request_is_valid(&request)) { return false; }
    request.offset = 0; request.save_pages = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.save_pages = 0; request.data_length = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.data_length = 0; request.operation = 30;
    const uint8_t probe[10] = {0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0};
    if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
        memcmp(command.cdb, probe, 10) != 0 || command.cdb_length != 10 || command.data != NULL ||
        command.data_length != 0 || command.direction != kSCSIDataTransfer_NoDataTransfer) { return false; }
    request.offset = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.offset = 0; request.operation = 31; request.data_length = 280;
    memcpy(request.data, "RDXSER01", 8); request.data[12] = 1;
    memcpy(request.data + 14, "0123456789", 10); memset(request.data + 24, 0xff, 256);
    const uint8_t write[10] = {0x3b, 2, 0x53, 0, 0, 0, 0, 1, 0x18, 0};
    if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
        memcmp(command.cdb, write, 10) != 0 || command.cdb_length != 10 || command.data != request.data ||
        command.data_length != 280 || command.direction != kSCSIDataTransfer_FromInitiatorToTarget) { return false; }
    const size_t fields[] = {0, 12, 13, 14, 24};
    for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
        uint8_t before = request.data[fields[index]]; request.data[fields[index]] = 0xfe;
        if (rdx_request_is_valid(&request)) { return false; }
        request.data[fields[index]] = before;
    }
    request.data[12] = 0;
    if (rdx_request_is_valid(&request)) { return false; }
    memset(request.data + 24, 0, 256);
    const uint8_t lanes[4] = {0x78, 0x56, 0x34, 0x12}; memcpy(request.data + 24, lanes, 4);
    if (!rdx_request_is_valid(&request)) { return false; }
    request.data[279] = 1;
    return !rdx_request_is_valid(&request);
}

/** Validates the manufacturing compare-and-replace wire boundary without device I/O. */
bool rdx_macos_test_manufacturing_restore_contract(void) {
    rdx_macos_scsi_request request = {
        .abi_version = RDX_MACOS_ABI_VERSION, .operation = 33, .timeout_ms = 30000
    };
    rdx_macos_scsi_result result = {0};
    rdx_scsi_command command = {0};
    const uint8_t probe[10] = {0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0};
    if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
        memcmp(command.cdb, probe, 10) != 0 || command.cdb_length != 10 || command.data != NULL ||
        command.data_length != 0 || command.direction != kSCSIDataTransfer_NoDataTransfer) { return false; }
    request.offset = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.offset = 0; request.save_pages = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.save_pages = 0; request.data_length = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.operation = 34; request.data_length = 528;
    memcpy(request.data, "RDXMFG01", 8);
    memset(request.data + 16, 0xa5, 256);
    const uint8_t lanes[4] = {0x78, 0x56, 0x34, 0x12};
    memcpy(request.data + 272, lanes, 4);
    const uint8_t write[10] = {0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0};
    if (!rdx_request_is_valid(&request) || !rdx_build_scsi_command(&request, &result, &command) ||
        memcmp(command.cdb, write, 10) != 0 || command.cdb_length != 10 || command.data != request.data ||
        command.data_length != 528 || command.direction != kSCSIDataTransfer_FromInitiatorToTarget) { return false; }
    const size_t fields[] = {0, 7, 12, 13, 14, 15, 272, 273, 274, 275, 524, 525, 526, 527};
    for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
        request.data[fields[index]] ^= 1;
        if (rdx_request_is_valid(&request)) { return false; }
        request.data[fields[index]] ^= 1;
    }
    request.offset = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.offset = 0; request.save_pages = 1;
    if (rdx_request_is_valid(&request)) { return false; }
    request.save_pages = 0; request.data_length = 527;
    if (rdx_request_is_valid(&request)) { return false; }
    request.data_length = 529;
    if (rdx_request_is_valid(&request)) { return false; }
    request.data_length = 528;
    memset(request.data + 16, 0xff, 256);
    if (!rdx_request_is_valid(&request)) { return false; }
    memset(request.data + 272, 0xff, 256);
    return !rdx_request_is_valid(&request);
}
