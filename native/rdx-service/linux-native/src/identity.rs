// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Race-resistant sysfs candidate recipes and exact block ancestry.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::block::{
    BlockBinding, BlockNodeProof, BlockTopology, resolve_block_node, validate_bdi_binding,
};
use crate::{MAX_CANDIDATES, MAX_SYSFS_ATTRIBUTE_BYTES, NativeError};

const MAX_SYMLINK_DEPTH: usize = 16;
// The hexadecimal recipe has 32 fixed bytes and must fit the parent's
// 1,024-byte private-locator bound after every path byte doubles.
const MAX_DEVPATH_BYTES: usize = 496;
const MAX_COMPONENT_BYTES: usize = 255;
const RECIPE_PREFIX: &str = "lnx1";

/// Exact Linux kernel device number.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DeviceNumber {
    major: u32,
    minor: u32,
}

impl DeviceNumber {
    /// Creates one exact major/minor pair.
    pub(crate) const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Formats the exact kernel class key used for block and BDI aliases.
    pub(crate) fn sysfs_key(self) -> String {
        format!("{}:{}", self.major, self.minor)
    }
}

/// Decodes Linux's split 64-bit `dev_t` layout without a C macro or FFI call.
pub(crate) const fn device_number_from_linux_dev_t(raw: u64) -> DeviceNumber {
    let major = ((raw >> 8) & 0xFFF) | ((raw >> 32) & 0xFFFF_F000);
    let minor = (raw & 0xFF) | ((raw >> 12) & 0xFFFF_FF00);
    DeviceNumber::new(major as u32, minor as u32)
}

/// Canonical roots used by target code and synthetic portable tests.
pub(crate) struct SysfsRoots {
    sys_root: PathBuf,
    class_root: PathBuf,
    devices_root: PathBuf,
}

impl SysfsRoots {
    /// Canonicalizes the exact class/devices roots beneath one sysfs root.
    pub(crate) fn new(class_root: PathBuf, devices_root: PathBuf) -> Result<Self, NativeError> {
        let class_root =
            fs::canonicalize(class_root).map_err(|_| NativeError::EnumerationFailed)?;
        let devices_root =
            fs::canonicalize(devices_root).map_err(|_| NativeError::EnumerationFailed)?;
        let Some(sys_root) = class_root.parent().and_then(Path::parent) else {
            return Err(NativeError::EnumerationFailed);
        };
        if class_root.strip_prefix(sys_root).ok() != Some(Path::new("class/scsi_generic"))
            || devices_root.strip_prefix(sys_root).ok() != Some(Path::new("devices"))
        {
            return Err(NativeError::EnumerationFailed);
        }
        Ok(Self {
            sys_root: sys_root.to_path_buf(),
            class_root,
            devices_root,
        })
    }

    /// Builds roots for the host's standard sysfs mount.
    #[cfg(target_os = "linux")]
    pub(crate) fn native() -> Result<Self, NativeError> {
        Self::new(
            PathBuf::from("/sys/class/scsi_generic"),
            PathBuf::from("/sys/devices"),
        )
    }

    /// Returns the canonical class directory.
    #[cfg(test)]
    pub(crate) fn class_root(&self) -> &Path {
        &self.class_root
    }

    /// Returns the canonical devices directory inside portable parsing code.
    pub(crate) fn devices_root(&self) -> &Path {
        &self.devices_root
    }

    /// Returns the canonical sysfs mount root inside parsing code and tests.
    pub(crate) fn sys_root(&self) -> &Path {
        &self.sys_root
    }
}

/// Exact candidate binding retained inside one opaque recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeviceBinding {
    sg_index: u32,
    relative_devpath: PathBuf,
    device_number: DeviceNumber,
}

impl DeviceBinding {
    /// Validates a relative sysfs path, sg name, and device number as one binding.
    pub(crate) fn new(
        sg_index: u32,
        relative_devpath: PathBuf,
        device_number: DeviceNumber,
    ) -> Result<Self, NativeError> {
        validate_relative_devpath(&relative_devpath, sg_index)?;
        Ok(Self {
            sg_index,
            relative_devpath,
            device_number,
        })
    }

    /// Returns the numeric sg suffix used to construct the private device node.
    pub(crate) const fn sg_index(&self) -> u32 {
        self.sg_index
    }

    /// Returns the exact canonical path relative to `/sys/devices`.
    pub(crate) fn relative_devpath(&self) -> &Path {
        &self.relative_devpath
    }

    /// Returns the exact character-device major/minor pair.
    #[cfg(test)]
    pub(crate) const fn device_number(&self) -> DeviceNumber {
        self.device_number
    }
}

/// File-type and device-number proof copied from one opened device descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenedDeviceProof {
    character_device: bool,
    device_number: DeviceNumber,
}

impl OpenedDeviceProof {
    /// Creates a pointer-free descriptor proof.
    pub(crate) const fn new(character_device: bool, device_number: DeviceNumber) -> Self {
        Self {
            character_device,
            device_number,
        }
    }
}

/// File type and stable directory identity copied from an open sysfs handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SysfsInstanceProof {
    directory: bool,
    filesystem_device: u64,
    inode: u64,
}

impl SysfsInstanceProof {
    /// Creates a pointer-free proof which never crosses the companion boundary.
    pub(crate) const fn new(directory: bool, filesystem_device: u64, inode: u64) -> Self {
        Self {
            directory,
            filesystem_device,
            inode,
        }
    }

    /// Returns whether the retained object was an exact directory.
    #[cfg(target_os = "linux")]
    pub(crate) const fn is_directory(&self) -> bool {
        self.directory
    }
}

/// One unvalidated scsi-generic candidate with retained native authority.
pub struct ScsiGenericCandidate {
    token: String,
    recipe: OsString,
    #[cfg(target_os = "linux")]
    retained: Option<crate::native::RetainedSysfsInstance>,
}

impl ScsiGenericCandidate {
    /// Returns the bounded path-free routing token.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the opaque recipe only to portable identity tests.
    #[cfg(test)]
    pub(crate) fn recipe(&self) -> &OsStr {
        &self.recipe
    }

    /// Decodes the private recipe for target-gated retention and promotion.
    #[cfg(target_os = "linux")]
    pub(crate) fn native_binding(&self) -> Result<DeviceBinding, NativeError> {
        decode_recipe(&self.recipe)
    }

    /// Attaches the exact sysfs handle acquired during this enumeration.
    #[cfg(target_os = "linux")]
    pub(crate) fn retain(&mut self, retained: crate::native::RetainedSysfsInstance) {
        self.retained = Some(retained);
    }

    /// Borrows retained enumeration authority for an independently checked open.
    #[cfg(target_os = "linux")]
    pub(crate) fn native_parts(
        &self,
    ) -> Result<(DeviceBinding, &crate::native::RetainedSysfsInstance), NativeError> {
        let binding = decode_recipe(&self.recipe)?;
        let retained = self.retained.as_ref().ok_or(NativeError::DeviceRemoved)?;
        Ok((binding, retained))
    }
}

impl PartialEq for ScsiGenericCandidate {
    /// Compares only portable candidate evidence; retained handles are authority.
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token && self.recipe == other.recipe
    }
}

impl Eq for ScsiGenericCandidate {}

impl std::fmt::Debug for ScsiGenericCandidate {
    /// Redacts sysfs and device-node identity.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScsiGenericCandidate")
            .field("token", &self.token)
            .field("recipe", &"<private>")
            .finish()
    }
}

/// Enumerates bounded sg candidates and skips invalid individual entries.
pub(crate) fn enumerate_candidates_at(
    roots: &SysfsRoots,
) -> Result<Vec<ScsiGenericCandidate>, NativeError> {
    let entries = bounded_sorted_entries(&roots.class_root)?;
    let mut candidates = Vec::new();
    for entry in entries {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(sg_index) = parse_sg_name(&name) else {
            continue;
        };
        let Ok(resolved) =
            resolve_componentwise(roots, Path::new("class/scsi_generic").join(&name))
        else {
            continue;
        };
        if !resolved.starts_with(&roots.devices_root)
            || resolved.file_name() != Some(OsStr::new(&name))
            || resolved.parent().and_then(Path::file_name) != Some(OsStr::new("scsi_generic"))
        {
            continue;
        }
        let Ok(relative_devpath) = resolved.strip_prefix(&roots.devices_root) else {
            continue;
        };
        let Ok(device_number) = read_device_number(&resolved.join("dev")) else {
            continue;
        };
        let Ok(binding) =
            DeviceBinding::new(sg_index, relative_devpath.to_path_buf(), device_number)
        else {
            continue;
        };
        candidates.push(ScsiGenericCandidate {
            token: format!("linux-sg-{sg_index}"),
            recipe: encode_recipe(&binding),
            #[cfg(target_os = "linux")]
            retained: None,
        });
    }
    Ok(candidates)
}

/// Resolves symlinks one component at a time without leaving the expected sysfs root.
fn resolve_componentwise(roots: &SysfsRoots, relative: PathBuf) -> Result<PathBuf, NativeError> {
    if relative.is_absolute() {
        return Err(NativeError::EnumerationFailed);
    }
    let mut current = roots.sys_root.clone();
    let mut pending = path_components(&relative)?;
    let mut symlink_depth = 0_usize;
    while let Some(component) = pending.pop_front() {
        match component.as_os_str().as_encoded_bytes() {
            b"." => continue,
            b".." => {
                if current == roots.sys_root
                    || !current.pop()
                    || !current.starts_with(&roots.sys_root)
                {
                    return Err(NativeError::EnumerationFailed);
                }
                continue;
            }
            bytes if bytes.is_empty() || bytes.len() > MAX_COMPONENT_BYTES => {
                return Err(NativeError::ResourceLimit);
            }
            _ => current.push(&component),
        }
        if !current.starts_with(&roots.sys_root) {
            return Err(NativeError::EnumerationFailed);
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| NativeError::EnumerationFailed)?;
        if metadata.file_type().is_symlink() {
            symlink_depth += 1;
            if symlink_depth > MAX_SYMLINK_DEPTH {
                return Err(NativeError::ResourceLimit);
            }
            let target = fs::read_link(&current).map_err(|_| NativeError::EnumerationFailed)?;
            current.pop();
            let target = if target.is_absolute() {
                let relative = target
                    .strip_prefix(&roots.sys_root)
                    .map_err(|_| NativeError::EnumerationFailed)?
                    .to_path_buf();
                current.clone_from(&roots.sys_root);
                relative
            } else {
                target
            };
            let target_components = path_components(&target)?;
            for component in target_components.into_iter().rev() {
                pending.push_front(component);
            }
        }
    }
    Ok(current)
}

/// Converts a relative path into a queue while retaining `..` for bounded resolution.
fn path_components(path: &Path) -> Result<VecDeque<OsString>, NativeError> {
    let mut components = VecDeque::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => components.push_back(value.to_owned()),
            Component::CurDir => components.push_back(OsString::from(".")),
            Component::ParentDir => components.push_back(OsString::from("..")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(NativeError::EnumerationFailed);
            }
        }
    }
    Ok(components)
}

/// Parses only canonical `sg` plus an unsigned decimal suffix.
fn parse_sg_name(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("sg")?;
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse().ok()
}

/// Reads one small regular sysfs attribute without following an attribute symlink.
fn read_bounded_attribute(path: &Path) -> Result<Vec<u8>, NativeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| NativeError::EnumerationFailed)?;
    if !metadata.file_type().is_file() {
        return Err(NativeError::EnumerationFailed);
    }
    // Sysfs reports page-sized or zero `st_size` values for small attributes,
    // so the actual bounded read is authoritative rather than metadata length.
    let file = fs::File::open(path).map_err(|_| NativeError::EnumerationFailed)?;
    let mut bytes = Vec::with_capacity(MAX_SYSFS_ATTRIBUTE_BYTES + 1);
    file.take((MAX_SYSFS_ATTRIBUTE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeError::EnumerationFailed)?;
    if bytes.len() > MAX_SYSFS_ATTRIBUTE_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    Ok(bytes)
}

/// Parses one exact sysfs `major:minor` attribute.
pub(crate) fn read_device_number(path: &Path) -> Result<DeviceNumber, NativeError> {
    let bytes = read_bounded_attribute(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| NativeError::EnumerationFailed)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.trim() != text || text.matches(':').count() != 1 {
        return Err(NativeError::EnumerationFailed);
    }
    let (major, minor) = text.split_once(':').ok_or(NativeError::EnumerationFailed)?;
    let major = major
        .parse::<u32>()
        .map_err(|_| NativeError::EnumerationFailed)?;
    let minor = minor
        .parse::<u32>()
        .map_err(|_| NativeError::EnumerationFailed)?;
    Ok(DeviceNumber::new(major, minor))
}

/// Validates the recipe's relative path shape and final sg component.
fn validate_relative_devpath(path: &Path, sg_index: u32) -> Result<(), NativeError> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_DEVPATH_BYTES
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.file_name() != Some(OsStr::new(&format!("sg{sg_index}")))
        || path.parent().and_then(Path::file_name) != Some(OsStr::new("scsi_generic"))
        || !bytes.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err(NativeError::InvalidRequest);
    }
    Ok(())
}

/// Encodes an exact binding into a versioned ASCII recipe without a `/dev` path.
fn encode_recipe(binding: &DeviceBinding) -> OsString {
    let mut path_hex = String::with_capacity(
        binding
            .relative_devpath
            .as_os_str()
            .as_encoded_bytes()
            .len()
            * 2,
    );
    for byte in binding.relative_devpath.as_os_str().as_encoded_bytes() {
        use std::fmt::Write;
        write!(&mut path_hex, "{byte:02X}").expect("writing to String cannot fail");
    }
    OsString::from(format!(
        "{RECIPE_PREFIX}:{:08X}:{:08X}:{:08X}:{path_hex}",
        binding.sg_index, binding.device_number.major, binding.device_number.minor,
    ))
}

/// Decodes one exact versioned binding recipe without accepting a device path.
pub(crate) fn decode_recipe(recipe: &OsStr) -> Result<DeviceBinding, NativeError> {
    let text = recipe.to_str().ok_or(NativeError::InvalidRequest)?;
    if text.len() > 1_024 || text.matches(':').count() != 4 {
        return Err(NativeError::InvalidRequest);
    }
    let mut fields = text.split(':');
    if fields.next() != Some(RECIPE_PREFIX) {
        return Err(NativeError::InvalidRequest);
    }
    let sg_index = parse_hex_u32(fields.next())?;
    let major = parse_hex_u32(fields.next())?;
    let minor = parse_hex_u32(fields.next())?;
    let encoded_path = fields.next().ok_or(NativeError::InvalidRequest)?;
    if fields.next().is_some() || encoded_path.is_empty() || encoded_path.len() % 2 != 0 {
        return Err(NativeError::InvalidRequest);
    }
    let mut bytes = Vec::with_capacity(encoded_path.len() / 2);
    for chunk in encoded_path.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).map_err(|_| NativeError::InvalidRequest)?;
        bytes.push(u8::from_str_radix(pair, 16).map_err(|_| NativeError::InvalidRequest)?);
    }
    let path = String::from_utf8(bytes).map_err(|_| NativeError::InvalidRequest)?;
    DeviceBinding::new(
        sg_index,
        PathBuf::from(path),
        DeviceNumber::new(major, minor),
    )
}

/// Parses one exact eight-digit hexadecimal recipe field.
fn parse_hex_u32(field: Option<&str>) -> Result<u32, NativeError> {
    let field = field.ok_or(NativeError::InvalidRequest)?;
    if field.len() != 8 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(NativeError::InvalidRequest);
    }
    u32::from_str_radix(field, 16).map_err(|_| NativeError::InvalidRequest)
}

/// Compares exact pre-open, descriptor, and post-open proofs against one recipe.
pub(crate) fn binding_is_stable(
    expected: &DeviceBinding,
    before: &DeviceBinding,
    opened: OpenedDeviceProof,
    after: &DeviceBinding,
) -> bool {
    opened.character_device
        && opened.device_number == expected.device_number
        && before == expected
        && after == expected
}

/// Compares the enumerated sysfs handle, current instance, SG descriptor, and
/// both current class-link snapshots as one atomic-promotion proof.
pub(crate) fn candidate_instance_is_stable(
    expected: &DeviceBinding,
    before: &DeviceBinding,
    retained_at_enumeration: SysfsInstanceProof,
    retained_now: SysfsInstanceProof,
    current_path: SysfsInstanceProof,
    opened: OpenedDeviceProof,
    after: &DeviceBinding,
) -> bool {
    retained_sysfs_instance_is_current(retained_at_enumeration, retained_now, current_path)
        && binding_is_stable(expected, before, opened, after)
}

/// Requires one retained sysfs directory to remain the exact current inode on
/// the same sysfs filesystem, even when its path and device number are reused.
pub(crate) fn retained_sysfs_instance_is_current(
    retained_at_open: SysfsInstanceProof,
    retained_now: SysfsInstanceProof,
    current_path: SysfsInstanceProof,
) -> bool {
    retained_at_open.directory
        && retained_at_open == retained_now
        && retained_at_open == current_path
}

/// Resolves the current class entry back into an exact recipe binding.
#[cfg(target_os = "linux")]
pub(crate) fn resolve_binding(
    roots: &SysfsRoots,
    sg_index: u32,
) -> Result<DeviceBinding, NativeError> {
    let name = format!("sg{sg_index}");
    let resolved = resolve_componentwise(roots, Path::new("class/scsi_generic").join(&name))?;
    if !resolved.starts_with(&roots.devices_root)
        || resolved.file_name() != Some(OsStr::new(&name))
        || resolved.parent().and_then(Path::file_name) != Some(OsStr::new("scsi_generic"))
    {
        return Err(NativeError::DeviceRemoved);
    }
    let relative = resolved
        .strip_prefix(&roots.devices_root)
        .map_err(|_| NativeError::DeviceRemoved)?;
    let number = read_device_number(&resolved.join("dev"))?;
    DeviceBinding::new(sg_index, relative.to_path_buf(), number)
}

/// Enumerates exact disk and partition identities below the bound SCSI ancestor.
#[cfg(test)]
pub(crate) fn block_bindings_for(
    roots: &SysfsRoots,
    binding: &DeviceBinding,
) -> Result<Vec<BlockBinding>, NativeError> {
    block_topology_for(roots, binding).map(|topology| topology.bindings)
}

/// Builds a retained, exact, single-device topology proof or fails closed for
/// device-mapper, LVM, crypt, multipath, spanned, or otherwise layered graphs.
pub(crate) fn block_topology_for(
    roots: &SysfsRoots,
    binding: &DeviceBinding,
) -> Result<BlockTopology, NativeError> {
    let device_root = find_scsi_device_ancestor(roots, binding)?;
    let scsi_device_relative = device_root
        .strip_prefix(roots.devices_root())
        .map_err(|_| NativeError::EnumerationFailed)?
        .to_path_buf();
    let block_root = device_root.join("block");
    match fs::symlink_metadata(&block_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BlockTopology {
                scsi_device_relative,
                bindings: Vec::new(),
                nodes: Vec::new(),
            });
        }
        _ => return Err(NativeError::EnumerationFailed),
    }
    let disks = bounded_sorted_entries(&block_root)?;

    let mut bindings = Vec::new();
    let mut nodes = Vec::new();
    let mut graph_roots = Vec::new();
    let mut disk_count = 0_usize;
    for disk in disks {
        let file_type = disk
            .file_type()
            .map_err(|_| NativeError::EnumerationFailed)?;
        if !file_type.is_dir() || file_type.is_symlink() {
            return Err(NativeError::EnumerationFailed);
        }
        disk_count += 1;
        if disk_count > 1 {
            return Err(NativeError::EvidenceIncomplete);
        }
        validate_real_directory(&disk.path(), roots.devices_root())?;
        require_block_subsystem(roots, &disk.path())?;
        let disk_name = validate_block_name(&disk.file_name())?;
        if disk_name.starts_with("dm-")
            || disk_name.starts_with("md")
            || disk.path().join("dm").exists()
            || disk.path().join("md").exists()
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        reject_partition_marker(&disk.path())?;
        let disk_number = read_device_number(&disk.path().join("dev"))?;
        let bdi = validate_bdi_binding(roots, &disk.path(), disk_number)?;
        bindings.push(BlockBinding {
            name: disk_name.clone(),
            device_number: disk_number,
        });
        nodes.push(BlockNodeProof {
            name: disk_name,
            relative_path: relative_device_path(roots, &disk.path())?,
            device_number: disk_number,
            partition: None,
            bdi: Some(bdi),
        });
        graph_roots.push(disk.path());

        for child in bounded_sorted_entries(&disk.path())? {
            let file_type = child
                .file_type()
                .map_err(|_| NativeError::EnumerationFailed)?;
            if file_type.is_symlink() {
                validate_known_block_symlink(roots, &child.path(), &child.file_name())?;
                continue;
            }
            if !file_type.is_dir() {
                continue;
            }
            if is_known_block_metadata_directory(&child.file_name()) {
                continue;
            }
            validate_real_directory(&child.path(), roots.devices_root())?;
            let name = validate_block_name(&child.file_name())?;
            let dev_path = child.path().join("dev");
            match fs::symlink_metadata(&dev_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(NativeError::EnumerationFailed);
                }
                Err(_) => return Err(NativeError::EnumerationFailed),
                Ok(_) => {}
            }
            let partition = read_positive_decimal_attribute(&child.path().join("partition"))?
                .ok_or(NativeError::EnumerationFailed)?;
            require_block_subsystem(roots, &child.path())?;
            let partition_number = read_device_number(&dev_path)?;
            bindings.push(BlockBinding {
                name: name.clone(),
                device_number: partition_number,
            });
            nodes.push(BlockNodeProof {
                name,
                relative_path: relative_device_path(roots, &child.path())?,
                device_number: partition_number,
                partition: Some(partition),
                bdi: None,
            });
            graph_roots.push(child.path());
        }
    }
    if bindings.len() > MAX_CANDIDATES {
        return Err(NativeError::ResourceLimit);
    }
    inspect_block_graph(roots, &graph_roots)?;
    bindings.sort_by(|left, right| left.name.cmp(&right.name));
    nodes.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let unique_names = bindings
        .iter()
        .map(|block| block.name.as_str())
        .collect::<BTreeSet<_>>();
    let unique_numbers = bindings
        .iter()
        .map(|block| block.device_number)
        .collect::<BTreeSet<_>>();
    if unique_names.len() != bindings.len() || unique_numbers.len() != bindings.len() {
        return Err(NativeError::EnumerationFailed);
    }
    for node in &nodes {
        if resolve_block_node(roots, node)? != *node {
            return Err(NativeError::EnumerationFailed);
        }
    }
    Ok(BlockTopology {
        scsi_device_relative,
        bindings,
        nodes,
    })
}

/// Finds the unique SCSI device by its exact subsystem and kernel device type,
/// without relying on a fixed number of parent pops from the sg class layout.
fn find_scsi_device_ancestor(
    roots: &SysfsRoots,
    binding: &DeviceBinding,
) -> Result<PathBuf, NativeError> {
    let mut current = roots.devices_root().join(binding.relative_devpath());
    validate_real_directory(&current, roots.devices_root())?;
    let expected = roots.sys_root().join("bus/scsi");
    let mut found = None;
    while current != roots.devices_root() {
        if subsystem_target(roots, &current)?.as_deref() == Some(expected.as_path()) {
            // Targets and hosts share the SCSI bus. Only the device type
            // binds a LUN's block tree; duplicated type evidence is ambiguous.
            let uevent = read_bounded_attribute(&current.join("uevent"))?;
            let mut types = uevent
                .split(|byte| *byte == b'\n')
                .filter_map(|line| line.strip_prefix(b"DEVTYPE="));
            let kind = types.next().ok_or(NativeError::EnumerationFailed)?;
            if types.next().is_some() {
                return Err(NativeError::EnumerationFailed);
            }
            match kind {
                b"scsi_device" => {
                    if found.replace(current.clone()).is_some() {
                        return Err(NativeError::EnumerationFailed);
                    }
                }
                b"scsi_target" | b"scsi_host" => {}
                _ => return Err(NativeError::EnumerationFailed),
            }
        }
        if !current.pop() || !current.starts_with(roots.devices_root()) {
            return Err(NativeError::EnumerationFailed);
        }
    }
    found.ok_or(NativeError::EnumerationFailed)
}

/// Returns one component-wise-resolved subsystem target, if present.
pub(crate) fn subsystem_target(
    roots: &SysfsRoots,
    node: &Path,
) -> Result<Option<PathBuf>, NativeError> {
    let link = node.join("subsystem");
    let metadata = match fs::symlink_metadata(&link) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(NativeError::EnumerationFailed),
    };
    if !metadata.file_type().is_symlink() {
        return Err(NativeError::EnumerationFailed);
    }
    resolve_sysfs_path(roots, &link).map(Some)
}

/// Requires the exact `/sys/class/block` subsystem identity.
pub(crate) fn require_block_subsystem(roots: &SysfsRoots, node: &Path) -> Result<(), NativeError> {
    if subsystem_target(roots, node)?.as_deref()
        != Some(roots.sys_root().join("class/block").as_path())
    {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(())
}

/// Resolves one existing absolute sysfs path through the bounded component-wise resolver.
pub(crate) fn resolve_sysfs_path(roots: &SysfsRoots, path: &Path) -> Result<PathBuf, NativeError> {
    let relative = path
        .strip_prefix(roots.sys_root())
        .map_err(|_| NativeError::EnumerationFailed)?;
    resolve_componentwise(roots, relative.to_path_buf())
}

/// Requires a canonical real directory confined to one expected root.
pub(crate) fn validate_real_directory(path: &Path, root: &Path) -> Result<(), NativeError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| NativeError::EnumerationFailed)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NativeError::EnumerationFailed);
    }
    let canonical = fs::canonicalize(path).map_err(|_| NativeError::EnumerationFailed)?;
    if canonical != path || !canonical.starts_with(root) {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(())
}

/// Converts one proven block node to its exact path relative to `/sys/devices`.
fn relative_device_path(roots: &SysfsRoots, path: &Path) -> Result<PathBuf, NativeError> {
    path.strip_prefix(roots.devices_root())
        .map(Path::to_path_buf)
        .map_err(|_| NativeError::EnumerationFailed)
}

/// Rejects a partition marker on a gendisk node while allowing absence.
pub(crate) fn reject_partition_marker(path: &Path) -> Result<(), NativeError> {
    match fs::symlink_metadata(path.join("partition")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(NativeError::EnumerationFailed),
        Err(_) => Err(NativeError::EnumerationFailed),
    }
}

/// Allows only known kernel metadata links and resolves each within sysfs.
fn validate_known_block_symlink(
    roots: &SysfsRoots,
    path: &Path,
    name: &OsStr,
) -> Result<(), NativeError> {
    match name.as_encoded_bytes() {
        b"subsystem" => {
            require_block_subsystem(roots, path.parent().ok_or(NativeError::EnumerationFailed)?)
        }
        b"bdi" => {
            let disk = path.parent().ok_or(NativeError::EnumerationFailed)?;
            let number = read_device_number(&disk.join("dev"))?;
            validate_bdi_binding(roots, disk, number).map(|_| ())
        }
        b"device" => resolve_sysfs_path(roots, path).and_then(|target| {
            target
                .starts_with(roots.devices_root())
                .then_some(())
                .ok_or(NativeError::EnumerationFailed)
        }),
        _ => Err(NativeError::EnumerationFailed),
    }
}

/// Identifies only metadata directories known not to represent partitions.
fn is_known_block_metadata_directory(name: &OsStr) -> bool {
    matches!(
        name.as_encoded_bytes(),
        b"holders" | b"slaves" | b"queue" | b"power" | b"mq" | b"integrity" | b"trace"
    )
}

/// Traverses the complete bounded holders/slaves graph with confinement and
/// cycle detection. Any graph edge or composite marker is unsupported evidence.
fn inspect_block_graph(roots: &SysfsRoots, starting: &[PathBuf]) -> Result<(), NativeError> {
    let mut queue = VecDeque::from(starting.to_vec());
    let mut visited = BTreeSet::new();
    let mut edges = BTreeSet::new();
    let mut composite = false;
    while let Some(node) = queue.pop_front() {
        if !visited.insert(node.clone()) {
            continue;
        }
        if visited.len() > MAX_CANDIDATES {
            return Err(NativeError::ResourceLimit);
        }
        validate_real_directory(&node, roots.devices_root())?;
        require_block_subsystem(roots, &node)?;
        let node_name =
            validate_block_name(node.file_name().ok_or(NativeError::EnumerationFailed)?)?;
        composite |= node_name.starts_with("dm-")
            || node_name.starts_with("md")
            || node.join("dm").exists()
            || node.join("md").exists();
        let partition = match fs::symlink_metadata(node.join("partition")) {
            Ok(_) => read_positive_decimal_attribute(&node.join("partition"))?.is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(NativeError::EnumerationFailed),
        };
        for relation in ["holders", "slaves"] {
            let relation_root = node.join(relation);
            match fs::symlink_metadata(&relation_root) {
                Err(error)
                    if relation == "slaves"
                        && partition
                        && error.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(_) => return Err(NativeError::EnumerationFailed),
                Ok(_) => {}
            }
            validate_real_directory(&relation_root, roots.devices_root())?;
            for entry in bounded_sorted_entries(&relation_root)? {
                if !entry
                    .file_type()
                    .map_err(|_| NativeError::EnumerationFailed)?
                    .is_symlink()
                {
                    return Err(NativeError::EnumerationFailed);
                }
                let target = resolve_sysfs_path(roots, &entry.path())?;
                if !target.starts_with(roots.devices_root()) {
                    return Err(NativeError::EnumerationFailed);
                }
                validate_real_directory(&target, roots.devices_root())?;
                require_block_subsystem(roots, &target)?;
                if edges.len() == MAX_CANDIDATES * 2 {
                    return Err(NativeError::ResourceLimit);
                }
                edges.insert((node.clone(), target.clone()));
                queue.push_back(target);
            }
        }
    }
    let cycle_detected = graph_has_cycle(&edges);
    if composite || cycle_detected || !edges.is_empty() {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

/// Detects a directed cycle in one already-bounded graph.
fn graph_has_cycle(edges: &BTreeSet<(PathBuf, PathBuf)>) -> bool {
    let mut complete = BTreeSet::new();
    let mut active = BTreeSet::new();
    edges
        .iter()
        .any(|(node, _)| graph_visit_has_cycle(node, edges, &mut active, &mut complete))
}

/// Performs one bounded depth-first cycle-detection visit.
fn graph_visit_has_cycle(
    node: &PathBuf,
    edges: &BTreeSet<(PathBuf, PathBuf)>,
    active: &mut BTreeSet<PathBuf>,
    complete: &mut BTreeSet<PathBuf>,
) -> bool {
    if active.contains(node) {
        return true;
    }
    if complete.contains(node) {
        return false;
    }
    active.insert(node.clone());
    for (_, target) in edges.iter().filter(|(source, _)| source == node) {
        if graph_visit_has_cycle(target, edges, active, complete) {
            return true;
        }
    }
    active.remove(node);
    complete.insert(node.clone());
    false
}

/// Reads one strictly positive decimal sysfs attribute.
pub(crate) fn read_positive_decimal_attribute(path: &Path) -> Result<Option<u32>, NativeError> {
    let bytes = read_bounded_attribute(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| NativeError::EnumerationFailed)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || text.trim() != text || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NativeError::EnumerationFailed);
    }
    let value = text
        .parse::<u32>()
        .map_err(|_| NativeError::EnumerationFailed)?;
    Ok((value != 0).then_some(value))
}

/// Reads and sorts a bounded directory without accepting partial enumeration.
fn bounded_sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>, NativeError> {
    let directory = fs::read_dir(path).map_err(|_| NativeError::EnumerationFailed)?;
    let mut entries = Vec::with_capacity(MAX_CANDIDATES);
    for entry in directory {
        if entries.len() == MAX_CANDIDATES {
            return Err(NativeError::ResourceLimit);
        }
        entries.push(entry.map_err(|_| NativeError::EnumerationFailed)?);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

/// Accepts only one kernel-generated block basename without path syntax.
fn validate_block_name(name: &OsStr) -> Result<String, NativeError> {
    let name = name.to_str().ok_or(NativeError::EnumerationFailed)?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'!' | b'.' | b'_' | b'-'))
    {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(name.to_owned())
}
