use std::ffi::OsStr;

use rdx_linux_native::{LinuxDevice, ScsiGenericCandidate};

fn main() {
    let device = LinuxDevice::open(OsStr::new("opaque")).unwrap();
    let _fd = device.raw_fd();
    let _path = device.path();
}

fn leak_recipe(candidate: ScsiGenericCandidate) {
    let _recipe = candidate.into_recipe();
}
