// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only fixed image classes; raw names and allocation bases never leave this module's policy.
use super::protocol::{Exception, Exit, Module};
use super::*;
use std::collections::HashMap;
use windows::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, QueryDosDeviceW, VOLUME_NAME_NT,
};
use windows::Win32::System::Memory::{MEM_IMAGE, MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

/// Exact kernel-derived NT image names; unknown or ambiguous namespace data never grants identity.
struct Names(Vec<(Vec<u16>, Module)>);
impl Names {
    /// Uses only the kernel system directory's fixed drive, never environment or all-drive enumeration.
    fn read() -> Self {
        let mut directory = vec![0u16; 32_768];
        // SAFETY: bounded writable UTF-16 output; no process or system mutation.
        let length = unsafe { GetSystemDirectoryW(Some(&mut directory)) } as usize;
        if length < 3 || length >= directory.len() {
            return Self(Vec::new());
        }
        directory.truncate(length);
        if directory[1] != u16::from(b':')
            || directory[2] != u16::from(b'\\')
            || !((b'A' as u16..=b'Z' as u16).contains(&directory[0])
                || (b'a' as u16..=b'z' as u16).contains(&directory[0]))
        {
            return Self(Vec::new());
        }
        let drive = [directory[0], directory[1], 0];
        let mut device = vec![0u16; 32_768];
        // SAFETY: exactly one fixed drive taken from kernel metadata; never NULL enumeration.
        let length = unsafe { QueryDosDeviceW(PCWSTR(drive.as_ptr()), Some(&mut device)) } as usize;
        if length < 2 || length > device.len() {
            return Self(Vec::new());
        }
        device.truncate(length);
        let entries = device
            .split(|v| *v == 0)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        if entries.len() != 1 || !device.ends_with(&[0, 0]) {
            return Self(Vec::new());
        }
        let mut root = entries[0].to_vec();
        root.extend_from_slice(&directory[2..]);
        let values = [
            ("ntdll.dll", Module::Ntdll),
            ("kernel32.dll", Module::Kernel32),
            ("kernelbase.dll", Module::KernelBase),
            ("advapi32.dll", Module::Advapi32),
            ("ucrtbase.dll", Module::Ucrt),
            ("vcruntime140.dll", Module::Vcruntime),
            ("vcruntime140_1.dll", Module::Vcruntime),
        ];
        Self(
            values
                .into_iter()
                .map(|(name, class)| {
                    let mut path = root.clone();
                    path.push(u16::from(b'\\'));
                    path.extend(name.encode_utf16());
                    (path, class)
                })
                .collect(),
        )
    }
    /// Compares complete paths; ASCII case-folding only can conservatively leave Unicode variants unknown.
    fn classify(&self, path: &[u16]) -> Module {
        if path.is_empty() || self.0.is_empty() {
            return Module::Unknown;
        }
        self.0
            .iter()
            .find(|(known, _)| {
                known.len() == path.len()
                    && known.iter().zip(path).all(|(a, b)| {
                        let fold = |v: u16| {
                            if (b'A' as u16..=b'Z' as u16).contains(&v) {
                                v + 32
                            } else {
                                v
                            }
                        };
                        fold(*a) == fold(*b)
                    })
            })
            .map(|(_, class)| *class)
            .unwrap_or(Module::Other)
    }
}
/// Only private bases from this retained owned child's events enter the bounded live map.
pub(super) struct Modules {
    names: Names,
    live: HashMap<usize, Module>,
}
impl Modules {
    /// Reads fixed system-path metadata once; API unavailability remains unknown.
    pub(super) fn new() -> Self {
        Self {
            names: Names::read(),
            live: HashMap::new(),
        }
    }
    /// Classifies an event file handle or its exact retained owned-child image mapping, without reads/writes.
    pub(super) fn load(
        &mut self,
        process: HANDLE,
        file: HANDLE,
        base: usize,
        fixture: bool,
    ) -> Module {
        let class = if fixture {
            Module::Fixture
        } else {
            let mut path = vec![0u16; 32_768];
            // SAFETY: event file handle is live and read only; no arbitrary path is opened.
            let length = if file.is_invalid() {
                0
            } else {
                (unsafe { GetFinalPathNameByHandleW(file, &mut path, VOLUME_NAME_NT) }) as usize
            };
            if length > 0 && length < path.len() {
                self.names.classify(&path[..length])
            } else {
                // SAFETY: address is only this exact event's retained base inside our owned child.
                let length =
                    unsafe { GetMappedFileNameW(process, base as *const _, &mut path) } as usize;
                if length > 0 && length < path.len() {
                    self.names.classify(&path[..length])
                } else {
                    Module::Unknown
                }
            }
        };
        if base != 0 && self.live.len() < 128 {
            self.live.insert(base, class);
        }
        class
    }
    /// Removes only a base that originated in this same connection's load events.
    pub(super) fn unload(&mut self, base: usize) {
        self.live.remove(&base);
    }
    /// An exception PC is classified only when exact SDK page metadata joins a live known image base.
    pub(super) fn exception(
        &self,
        process: HANDLE,
        address: *const core::ffi::c_void,
    ) -> (Module, bool) {
        let mut information = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: query-only retained owned process; bounded exact SDK output, no process memory read.
        let length = unsafe {
            VirtualQueryEx(
                process,
                Some(address),
                &mut information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if length != size_of::<MEMORY_BASIC_INFORMATION>() || information.Type != MEM_IMAGE {
            return (Module::Unknown, false);
        }
        self.live
            .get(&(information.AllocationBase as usize))
            .copied()
            .map(|class| (class, true))
            .unwrap_or((Module::Unknown, false))
    }
}
impl Module {
    /// Only these static category labels can reach stdout.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fixture => "fixture",
            Self::Ntdll => "ntdll",
            Self::Kernel32 => "kernel32",
            Self::KernelBase => "kernelbase",
            Self::Advapi32 => "advapi32",
            Self::Ucrt => "ucrt",
            Self::Vcruntime => "vcruntime",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}
impl Exception {
    /// Exact exception codes alone are classified; ordinary API errors are never converted to exceptions.
    pub(super) fn from_code(code: u32) -> Self {
        match code {
            0x8000_0003 => Self::Breakpoint,
            0xc000_0022 => Self::AccessDenied,
            0xc000_0005 => Self::AccessViolation,
            0xc000_0006 => Self::InPageError,
            0xc000_0142 => Self::DllInitFailed,
            _ => Self::Other,
        }
    }
    /// No raw exception record or address can be formatted.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Breakpoint => "breakpoint",
            Self::AccessDenied => "access-denied",
            Self::AccessViolation => "access-violation",
            Self::InPageError => "in-page-error",
            Self::DllInitFailed => "dll-init-failed",
            Self::Other => "other",
        }
    }
}
impl Exit {
    /// Retains only known fixture/loader categories; an unexpected code never proves execution.
    pub(super) fn from_code(code: u32) -> Self {
        match code {
            0xc000_0142 => Self::DllInitFailed,
            0 => Self::Success,
            17..=36 => Self::SelfCheck,
            _ => Self::Other,
        }
    }
}
