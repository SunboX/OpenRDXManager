// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Task-one ordinary donor observer/copy only: no child, token setter or production authority.
use super::manager_source_protocol::{
    self as policy, Admission, Boundary, CallerFacts, Candidate, DonorFacts,
};
use super::process_dacl_control::process_descriptor::Components;
use super::process_dacl_control::{PrivateDescriptor, source_default_dacl};
use super::token_statistics::Statistics;
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, FILETIME};
use windows::Win32::Security::{
    DuplicateTokenEx, IsWellKnownSid, SecurityImpersonation, TOKEN_READ_CONTROL, TokenPrimary,
    WinBatchSid, WinBuiltinAdministratorsSid, WinInteractiveSid, WinLocalServiceSid,
    WinLocalSystemSid, WinNetworkServiceSid, WinServiceSid,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{GetProcessId, GetProcessTimes, PROCESS_SYNCHRONIZE};

const MANAGER: &str = r"C:\Program Files\OpenRDXManager\OpenRDXManager.exe";
const ENROLLMENT: &str = r"C:\ProgramData\OpenRDXManager\LocalTrust\runtime.json";

/// Closed task-one phases are not the later child proof or any existing mode.
#[derive(Clone, Copy)]
enum Phase {
    Caller,
    Runtime,
    Discovery,
    Donor,
    Duplicate,
    Copy,
    CallerCheck,
    DonorCheck,
    CopyCheck,
    Complete,
}
impl Phase {
    /// Returns compiled schema names, never process-provided content.
    fn name(self) -> &'static str {
        match self {
            Self::Caller => "caller",
            Self::Runtime => "runtime",
            Self::Discovery => "donor-discovery",
            Self::Donor => "donor-proof",
            Self::Duplicate => "duplicate",
            Self::Copy => "copy-proof",
            Self::CallerCheck => "caller-check",
            Self::DonorCheck => "donor-check",
            Self::CopyCheck => "copy-check",
            Self::Complete => "complete",
        }
    }
}
/// Emits a closed phase and fieldless error only, preserving the original operation result.
fn checkpoint<T>(
    phase: Phase,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    println!(
        "openrdx-manager-source-task-one-stage phase={} status=begin",
        phase.name()
    );
    let result = operation();
    match &result {
        Ok(_) => println!(
            "openrdx-manager-source-task-one-stage phase={} status=ok",
            phase.name()
        ),
        Err(error) => println!(
            "openrdx-manager-source-task-one-stage phase={} status=failed reason={error:?}",
            phase.name()
        ),
    }
    result
}
/// Private complete bounded token state, never Debug or raw buffer output.
struct State {
    snapshot: SourceSnapshot,
    descriptor: Components,
    default: Option<Vec<u8>>,
    statistics: Statistics,
}
impl State {
    /// Reads owner/group/DACL/LABEL, exact statistics and all source-context properties.
    fn read(token: &OwnedHandle) -> Result<Self, NativeError> {
        let statistics = Statistics::read(token);
        if !statistics.query_ok || !statistics.layout_valid {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(Self {
            snapshot: SourceSnapshot::read(token)?,
            descriptor: PrivateDescriptor::read(token.0)?.components,
            default: source_default_dacl(token)?,
            statistics,
        })
    }
    /// Requires known same object/logon and unchanged full properties/default ACL/object descriptor.
    fn same(&self, previous: &Self) -> Result<(), NativeError> {
        let ids = self.statistics.compare(previous.statistics);
        let properties = self.snapshot == previous.snapshot;
        let default = self.default == previous.default;
        let descriptor = self.descriptor == previous.descriptor;
        println!(
            "openrdx-manager-source-task-one-preservation query-ok=true instance-known={} instance-equal={} logon-equal={} modified-equal={} properties-equal={properties} default-dacl-equal={default} descriptor-equal={descriptor}",
            ids[0], ids[1], ids[2], ids[3]
        );
        if !policy::preserved(ids, [properties, default, descriptor]) {
            return Err(denial(Boundary::Preservation));
        }
        Ok(())
    }
}
/// Converts only fixed internal boundary categories; SDK errors use their existing NativeError mapping.
fn denial(boundary: Boundary) -> NativeError {
    match boundary {
        Boundary::Unavailable => NativeError::EvidenceIncomplete,
        Boundary::Ambiguous => NativeError::Busy,
        Boundary::Identity | Boundary::SourcePolicy | Boundary::Preservation => {
            NativeError::AccessDenied
        }
    }
}
/// Checks the shared native deadline before each bounded observer phase/chunk.
fn budget(deadline: Instant) -> Result<(), NativeError> {
    if Instant::now() >= deadline {
        Err(NativeError::TimedOut)
    } else {
        Ok(())
    }
}
/// Opens only the specified held process token with the exact read/duplicate rights required here.
fn observe_token(process: HANDLE, duplicate: bool) -> Result<OwnedHandle, NativeError> {
    let mut raw = HANDLE::default();
    // SAFETY: valid retained or current-process handle; no mutation rights are requested.
    unsafe {
        OpenProcessToken(
            process,
            TOKEN_QUERY
                | TOKEN_READ_CONTROL
                | if duplicate {
                    TOKEN_DUPLICATE
                } else {
                    windows::Win32::Security::TOKEN_ACCESS_MASK(0)
                },
            &mut raw,
        )
    }
    .map_err(map_native_error)?;
    Ok(OwnedHandle(raw))
}
/// Current elevated interactive caller, distinct from the ordinary donor and never duplicated.
struct Caller {
    token: OwnedHandle,
    state: State,
    console: OwnedSid,
    session: u32,
}
impl Caller {
    /// Captures caller before any donor duplicate rights; different-account UAC remains possible.
    fn capture() -> Result<Self, NativeError> {
        let token = observe_token(unsafe { GetCurrentProcess() }, false)?;
        let state = State::read(&token)?;
        // SAFETY: read-only global console query has no handle/pointer preconditions.
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        if session == u32::MAX {
            return Err(denial(Boundary::Unavailable));
        }
        let console = console_sid(session)?;
        let snapshot = &state.snapshot;
        let enabled_role = |role| {
            snapshot.groups.iter().any(|(sid, attributes)| {
                // SAFETY: SourceSnapshot owns complete validated SID copies.
                (unsafe { IsWellKnownSid(PSID(sid.as_ptr().cast_mut().cast()), role).as_bool() })
                    && policy::enabled_group(*attributes)
            })
        };
        let builtin_admin = enabled_role(WinBuiltinAdministratorsSid);
        let interactive_enabled = enabled_role(WinInteractiveSid);
        let service_enabled = enabled_role(WinServiceSid);
        let batch_enabled = enabled_role(WinBatchSid);
        let service = [WinLocalSystemSid, WinLocalServiceSid, WinNetworkServiceSid]
            .iter()
            .any(|role| {
                // SAFETY: token user SID was validated before it was copied into State.
                unsafe {
                    IsWellKnownSid(PSID(snapshot.user.as_ptr().cast_mut().cast()), *role).as_bool()
                }
            });
        let admitted = policy::caller_allowed(&CallerFacts {
            query_known: true,
            elevated: snapshot.elevation != 0,
            high: snapshot.integrity == 0x3000,
            primary: snapshot.token_type == 1,
            active_console_session: snapshot.session == session,
            builtin_admin,
            not_service_principal: !service,
            interactive_enabled,
            service_enabled,
            batch_enabled,
        });
        println!(
            "openrdx-manager-source-task-one-caller query-ok=true elevated-admin={admitted} interactive-enabled={interactive_enabled} service-enabled={service_enabled} batch-enabled={batch_enabled} active-console-session={}",
            snapshot.session == session
        );
        if !admitted {
            return Err(denial(Boundary::SourcePolicy));
        }
        Ok(Self {
            token,
            state,
            console,
            session,
        })
    }
    /// Reads held AND current primary token so an old observer cannot hide token replacement.
    fn unchanged(&self) -> Result<(), NativeError> {
        policy::preservation_result([
            (|| State::read(&self.token)?.same(&self.state))(),
            (|| {
                // SAFETY: current-process handle is borrowed; observer requests query/read-control only.
                let current = observe_token(unsafe { GetCurrentProcess() }, false)?;
                State::read(&current)?.same(&self.state)
            })(),
            (|| {
                // SAFETY: read-only active-console query has no pointer/handle preconditions.
                if self.session != unsafe { WTSGetActiveConsoleSessionId() }
                    || self.console.bytes() != console_sid(self.session)?.bytes()
                {
                    return Err(denial(Boundary::Identity));
                }
                Ok(())
            })(),
        ])
    }
}
/// Fixed pinned file with private identity/hash, never already-mapped-image evidence.
struct FilePin {
    file: File,
    identity: FileIdentity,
    digest: [u8; 32],
}
impl FilePin {
    /// Opens an exact compiled runtime path after the complete runtime lease was acquired.
    fn open(path: &Path, deadline: Instant) -> Result<Self, NativeError> {
        let mut file = crate::local_trust::windows::open(path, false)?;
        crate::local_trust::validate_runtime_acl(&crate::local_trust::windows::evidence(&file)?)?;
        let identity = held_identity(&file)?;
        let digest = hash(&mut file, deadline)?;
        Ok(Self {
            file,
            identity,
            digest,
        })
    }
    /// Rechecks only retained bytes/metadata and exact fixed pathname identity without replacing pins.
    fn unchanged(&mut self, path: &Path, deadline: Instant) -> Result<(), NativeError> {
        budget(deadline)?;
        let current = crate::local_trust::windows::open(path, false)?;
        crate::local_trust::validate_runtime_acl(&crate::local_trust::windows::evidence(
            &self.file,
        )?)?;
        crate::local_trust::validate_runtime_acl(&crate::local_trust::windows::evidence(
            &current,
        )?)?;
        if held_identity(&self.file)? != self.identity
            || held_identity(&current)? != self.identity
            || hash(&mut self.file, deadline)? != self.digest
        {
            return Err(denial(Boundary::Preservation));
        }
        Ok(())
    }
}
/// Reads exact identity from a live pinned file, never from a process pathname by inference.
fn held_identity(file: &File) -> Result<FileIdentity, NativeError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file's borrowed handle stays live, output is initialized writable SDK storage.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(map_native_error)?;
    Ok(FileIdentity {
        volume: information.dwVolumeSerialNumber,
        index_high: information.nFileIndexHigh,
        index_low: information.nFileIndexLow,
    })
}
/// Bounded digest of a retained current runtime file; no digest or length is emitted.
fn hash(file: &mut File, deadline: Instant) -> Result<[u8; 32], NativeError> {
    let length = file.metadata().map_err(|_| NativeError::Other)?.len();
    if length == 0 || length > 1024 * 1024 * 1024 {
        return Err(NativeError::ResourceLimit);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| NativeError::Other)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut bytes = [0_u8; 65536];
    loop {
        budget(deadline)?;
        let count = file.read(&mut bytes).map_err(|_| NativeError::Other)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|n| *n <= length)
            .ok_or(NativeError::Other)?;
        digest.update(&bytes[..count]);
    }
    if total != length {
        return Err(NativeError::Other);
    }
    Ok(digest.finalize().into())
}
/// Pinned complete enrollment/runtime plus independently pinned current Manager/policy files.
struct RuntimePins {
    _lease: crate::local_trust::windows::RuntimeLease,
    image: FilePin,
    enrollment: FilePin,
}
impl RuntimePins {
    /// Existing enrolled trust only; never prepares enrollment, installs or changes the runtime.
    fn capture(deadline: Instant) -> Result<Self, NativeError> {
        let lease = crate::local_trust::windows::verify_runtime_lease()?;
        budget(deadline)?;
        Ok(Self {
            _lease: lease,
            image: FilePin::open(Path::new(MANAGER), deadline)?,
            enrollment: FilePin::open(Path::new(ENROLLMENT), deadline)?,
        })
    }
    /// Preserves the separately pinned current on-disk generation, not the donor's mapped generation.
    fn unchanged(&mut self, deadline: Instant) -> Result<(), NativeError> {
        policy::preservation_result([
            self.image.unchanged(Path::new(MANAGER), deadline),
            self.enrollment.unchanged(Path::new(ENROLLMENT), deadline),
        ])
    }
}
/// Query/synchronize-owned process retained from fixed bounded discovery; never termination authority.
struct ProcessLease {
    handle: OwnedHandle,
    record: Candidate,
}
/// Snapshot row owns a handle only when it is not the already retained donor.
struct Row {
    handle: Option<OwnedHandle>,
    record: Candidate,
}
/// Queries a retained process path/session/creation time and liveness; no file-by-path mapping claim.
fn process_record(
    handle: HANDLE,
    key: u32,
    parent: u32,
    session: u32,
) -> Result<Option<Candidate>, NativeError> {
    if unsafe { GetProcessId(handle) } != key {
        return Err(denial(Boundary::Identity));
    }
    let mut actual_session = u32::MAX;
    // SAFETY: initialized writable scalar; key was paired with the retained process handle.
    unsafe { ProcessIdToSessionId(key, &mut actual_session) }.map_err(map_native_error)?;
    if actual_session != session {
        return Ok(None);
    }
    let mut image = vec![0_u16; 32768];
    let mut length = image.len() as u32;
    // SAFETY: retained query handle and bounded writable UTF-16 output.
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(image.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(map_native_error)?;
    if length == 0 || length as usize >= image.len() {
        return Err(denial(Boundary::Identity));
    }
    let path = String::from_utf16(&image[..length as usize])
        .map_err(|_| NativeError::EvidenceIncomplete)?;
    if !path.eq_ignore_ascii_case(MANAGER) {
        return Ok(None);
    }
    // SAFETY: process handle includes SYNCHRONIZE; zero-time observation never changes it.
    if unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT {
        return Err(denial(Boundary::Identity));
    }
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all outputs are writable SDK scalars; the query-owned process remains held.
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(map_native_error)?;
    let born = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
    Ok(Some(Candidate { key, parent, born }))
}
/// At most 4,096 rows/32 handles/5 seconds, only fixed-name candidates; no unrelated token enumeration.
fn discover(
    session: u32,
    deadline: Instant,
    retained: Option<&ProcessLease>,
) -> Result<(Vec<Row>, usize), NativeError> {
    let until = deadline.min(Instant::now() + Duration::from_secs(5));
    // SAFETY: read-only process snapshot, no INHERIT flag or arbitrary process/module selection.
    let snapshot = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(map_native_error)?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: exact initialized SDK struct and owned snapshot.
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut rows = Vec::new();
    let mut records = 0;
    loop {
        budget(until)?;
        if is_error(&next, ERROR_NO_MORE_FILES) {
            break;
        }
        next.map_err(map_native_error)?;
        records += 1;
        if records > 4096 {
            return Err(NativeError::ResourceLimit);
        }
        let end = entry
            .szExeFile
            .iter()
            .position(|u| *u == 0)
            .ok_or(NativeError::EvidenceIncomplete)?;
        let name = String::from_utf16(&entry.szExeFile[..end])
            .map_err(|_| NativeError::EvidenceIncomplete)?;
        if name.eq_ignore_ascii_case("OpenRDXManager.exe") {
            if rows.len() + usize::from(retained.is_some()) >= 32 {
                return Err(NativeError::ResourceLimit);
            }
            let reused = retained.filter(|source| source.record.key == entry.th32ProcessID);
            let opened = if reused.is_none() {
                // SAFETY: name selects only a query candidate; no mutation/VM/read-memory/termination rights.
                Some(OwnedHandle(
                    unsafe {
                        OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                            false,
                            entry.th32ProcessID,
                        )
                    }
                    .map_err(map_native_error)?,
                ))
            } else {
                None
            };
            let handle = reused
                .map(|source| source.handle.0)
                .or_else(|| opened.as_ref().map(|h| h.0))
                .ok_or(NativeError::Other)?;
            if let Some(record) = process_record(
                handle,
                entry.th32ProcessID,
                entry.th32ParentProcessID,
                session,
            )? {
                rows.push(Row {
                    handle: opened,
                    record,
                });
            }
        }
        // SAFETY: same live snapshot and exact initialized output struct.
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    rows.sort_by_key(|row| row.record.key);
    let candidates = rows.iter().map(|row| row.record).collect::<Vec<_>>();
    let root =
        policy::select_root(&candidates, records, true, Instant::now() < until).map_err(denial)?;
    Ok((rows, root))
}
/// Privately retained ordinary donor; no raw handle adoption, token setter or mutable source API.
struct DonorLease {
    caller: Caller,
    runtime: RuntimePins,
    process: ProcessLease,
    graph: Vec<Candidate>,
    observer: OwnedHandle,
    state: State,
    deadline: Instant,
}
impl DonorLease {
    /// Acquires a real ordinary donor without launching Manager or granting pipe delegation.
    fn acquire_fixed() -> Result<Self, NativeError> {
        let deadline = Instant::now() + Duration::from_secs(90);
        let caller = checkpoint(Phase::Caller, Caller::capture)?;
        let result = (|| {
            let runtime = checkpoint(Phase::Runtime, || RuntimePins::capture(deadline))?;
            let (mut rows, root) = checkpoint(Phase::Discovery, || {
                discover(caller.session, deadline, None)
            })?;
            let graph = rows.iter().map(|row| row.record).collect::<Vec<_>>();
            let selected = rows.swap_remove(root);
            drop(rows);
            let process = ProcessLease {
                handle: selected.handle.ok_or(NativeError::Other)?,
                record: selected.record,
            };
            let (observer, state) = checkpoint(Phase::Donor, || {
                let observer = observe_token(process.handle.0, false)?;
                let state = State::read(&observer)?;
                let (_, no_enabled_admins) = administrative_groups(&observer)?;
                let facts = ordinary(&state, &caller, no_enabled_admins);
                if !policy::source_allowed(&facts) {
                    return Err(denial(Boundary::SourcePolicy));
                }
                println!(
                    "openrdx-manager-source-task-one-donor query-ok=true ordinary-medium=true no-enabled-admins=true caller-user-equal={} mapped-generation-known=false",
                    state.snapshot.user == caller.state.snapshot.user
                );
                Ok((observer, state))
            })?;
            Ok((runtime, process, graph, observer, state))
        })();
        // A failed acquisition still checks the captured caller; preserve the original error first.
        let caller_check = checkpoint(Phase::CallerCheck, || caller.unchanged());
        let (runtime, process, graph, observer, state) = result?;
        let mut lease = Self {
            caller,
            runtime,
            process,
            graph,
            observer,
            state,
            deadline,
        };
        let donor_check = checkpoint(Phase::DonorCheck, || lease.revalidate());
        policy::preservation_result([caller_check, donor_check])?;
        Ok(lease)
    }
    /// Checks held/current primary state, kernel path, full candidate graph and current-runtime pins.
    fn revalidate(&mut self) -> Result<(), NativeError> {
        budget(self.deadline)?;
        policy::preservation_result([
            self.caller.unchanged(),
            (|| State::read(&self.observer)?.same(&self.state))(),
            (|| {
                let current = observe_token(self.process.handle.0, false)?;
                let state = State::read(&current)?;
                state.same(&self.state)?;
                let (_, no_enabled_admins) = administrative_groups(&current)?;
                if !policy::source_allowed(&ordinary(&state, &self.caller, no_enabled_admins)) {
                    return Err(denial(Boundary::SourcePolicy));
                }
                Ok(())
            })(),
            (|| {
                let (rows, root) =
                    discover(self.caller.session, self.deadline, Some(&self.process))?;
                let graph = rows.iter().map(|row| row.record).collect::<Vec<_>>();
                if !policy::same_discovery(&self.graph, &graph, self.process.record, root) {
                    return Err(denial(Boundary::Identity));
                }
                Ok(())
            })(),
            self.runtime.unchanged(self.deadline),
        ])
    }
    /// Duplicates only the retained donor's current primary token; no owner/ACL/reduction changes.
    fn duplicate_primary(&mut self) -> Result<OrdinaryCopy, NativeError> {
        self.revalidate()?;
        let source = observe_token(self.process.handle.0, true)?;
        State::read(&source)?.same(&self.state)?;
        self.revalidate()?;
        let mut raw = HANDLE::default();
        // SAFETY: source is a fresh checked same-instance primary token; NULL attrs cannot set owner.
        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
        unsafe {
            DuplicateTokenEx(
                source.0,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_READ_CONTROL,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut raw,
            )
        }
        .map_err(map_native_error)?;
        let handle = OwnedHandle(raw);
        let state = State::read(&handle)?;
        let ids = state.statistics.compare(self.state.statistics);
        let properties = state.snapshot == self.state.snapshot;
        let default = state.default == self.state.default;
        println!(
            "openrdx-manager-source-task-one-copy query-ok=true instance-known={} copy-distinct={} logon-equal={} modified-equal={} properties-equal={properties} default-dacl-equal={default}",
            ids[0],
            ids[0] && !ids[1],
            ids[2],
            ids[3]
        );
        if !policy::duplicate_allowed(ids, properties, default) {
            return Err(denial(Boundary::Preservation));
        }
        self.revalidate()?;
        Ok(OrdinaryCopy { handle, state })
    }
}
/// Ordinary source policy is deliberately independent of the old maximum-reduction ceiling.
fn ordinary(state: &State, caller: &Caller, no_enabled_admins: bool) -> DonorFacts {
    let s = &state.snapshot;
    DonorFacts {
        runtime: true,
        image: true,
        instance: true,
        live: true,
        console_user: s.user == caller.console.bytes(),
        console_session: s.session == caller.session,
        primary: s.token_type == 1,
        non_elevated: s.elevation == 0,
        medium: s.integrity == 0x2000,
        no_enabled_admins,
        ui_access_zero: s.ui_access == 0,
        sandbox_inert_zero: s.sandbox_inert == 0,
        recognized_type: matches!(s.elevation_type, 1 | 3),
    }
}
/// Only owns DuplicateTokenEx output; there is no raw adoption, setter or launch in Task One.
struct OrdinaryCopy {
    handle: OwnedHandle,
    state: State,
}
impl OrdinaryCopy {
    /// Fresh independent preservation of this copy and donor, without broadening either handle.
    fn unchanged(&self, donor: &mut DonorLease) -> Result<(), NativeError> {
        policy::preservation_result([
            (|| State::read(&self.handle)?.same(&self.state))(),
            donor.revalidate(),
        ])
    }
}
/// Read-and-copy checkpoint only; no fixture creation, child launch or ordinary-gate authorization.
fn observe_manager_source() -> Result<(), NativeError> {
    let mut donor = DonorLease::acquire_fixed()?;
    let copy = checkpoint(Phase::Duplicate, || donor.duplicate_primary());
    let proof = match &copy {
        Ok(copy) => checkpoint(Phase::Copy, || {
            let state = State::read(&copy.handle)?;
            let (_, no_enabled_admins) = administrative_groups(&copy.handle)?;
            let facts = ordinary(&state, &donor.caller, no_enabled_admins);
            let admission = Admission {
                donor: facts,
                duplicate_exact: state.snapshot == donor.state.snapshot,
                source_unchanged: true,
                copy_unchanged: true,
                fresh: true,
                remaining_ms: donor
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            };
            if !policy::may_launch(&admission)
                || !policy::caller_observation(
                    Some(state.snapshot.user == donor.caller.state.snapshot.user),
                    true,
                )
            {
                return Err(denial(Boundary::Preservation));
            }
            copy.unchanged(&mut donor)
        }),
        Err(_) => Ok(()),
    };
    // Independent observations run even after copy/proof failure, and never mask its primary error.
    let caller_check = checkpoint(Phase::CallerCheck, || donor.caller.unchanged());
    let donor_check = checkpoint(Phase::DonorCheck, || donor.revalidate());
    let copy_check = match &copy {
        Ok(copy) => checkpoint(Phase::CopyCheck, || copy.unchanged(&mut donor)),
        Err(_) => Ok(()),
    };
    copy?;
    proof?;
    caller_check?;
    donor_check?;
    copy_check?;
    checkpoint(Phase::Complete, || {
        println!(
            "openrdx-manager-source-task-one-complete donor-copy-proof=true child-created=false startup-proof=false production-authority=false mapped-generation-known=false"
        );
        Ok(())
    })
}
/// Opt-in actual desktop checkpoint; unavailable donor/rights remain native failures, never skips.
#[test]
#[ignore = "requires approved enrolled Windows desktop and ordinary installed Manager donor"]
fn native_authenticated_manager_donor_duplication_proof() {
    let result = observe_manager_source();
    assert!(result.is_ok(), "manager-source-task-one-failed");
}
