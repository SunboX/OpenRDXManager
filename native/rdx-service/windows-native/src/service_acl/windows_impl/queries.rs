// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded read-only SCM queries shared by verification and provisioning.
use super::*;

/// Queries one bounded service configuration with validated embedded pointers.
pub(super) fn query_service_configuration(
    service: &OwnedService,
) -> Result<ServiceConfiguration, NativeError> {
    let mut needed = 0_u32;
    // SAFETY: null output with zero length is the documented sizing query.
    let sizing = unsafe { QueryServiceConfigW(service.0, None, 0, &mut needed) };
    if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
        || !(size_of::<QUERY_SERVICE_CONFIGW>()..=MAX_SERVICE_CONFIG_BYTES)
            .contains(&(needed as usize))
    {
        return Err(NativeError::Other);
    }
    let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = storage.len() * size_of::<usize>();
    let pointer = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // SAFETY: aligned storage is writable and remains live for pointer validation.
    unsafe { QueryServiceConfigW(service.0, Some(pointer), capacity as u32, &mut needed) }
        .map_err(map_native_error)?;
    if !(size_of::<QUERY_SERVICE_CONFIGW>()..=capacity).contains(&(needed as usize)) {
        return Err(NativeError::Other);
    }
    // SAFETY: successful query initialized the aligned leading configuration.
    let config = unsafe { pointer.read() };
    Ok(ServiceConfiguration {
        service_type: config.dwServiceType.0,
        start_type: config.dwStartType.0,
        error_control: config.dwErrorControl.0,
        binary_command: bounded_wide(&storage, needed as usize, config.lpBinaryPathName.0)?,
        account: bounded_wide(&storage, needed as usize, config.lpServiceStartName.0)?,
        dependencies: bounded_multi_wide(&storage, needed as usize, config.lpDependencies.0)?,
        load_order_group: bounded_wide(&storage, needed as usize, config.lpLoadOrderGroup.0)?,
    })
}

/// Reads one bounded service security descriptor.
pub(super) fn read_service_security(service: &OwnedService) -> Result<Vec<usize>, NativeError> {
    let mut needed = 0_u32;
    // SAFETY: null output with zero length is the documented sizing query.
    let sizing = unsafe {
        windows::Win32::System::Services::QueryServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION.0,
            None,
            0,
            &mut needed,
        )
    };
    if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER)
        || !(size_of::<SECURITY_DESCRIPTOR>()..=MAX_SECURITY_DESCRIPTOR_BYTES)
            .contains(&(needed as usize))
    {
        return Err(NativeError::Other);
    }
    let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = storage.len() * size_of::<usize>();
    // SAFETY: aligned storage is writable for its bounded exact capacity.
    unsafe {
        windows::Win32::System::Services::QueryServiceObjectSecurity(
            service.0,
            DACL_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast())),
            capacity as u32,
            &mut needed,
        )
    }
    .map_err(map_native_error)?;
    if !(size_of::<SECURITY_DESCRIPTOR>()..=capacity).contains(&(needed as usize)) {
        return Err(NativeError::Other);
    }
    Ok(storage)
}
