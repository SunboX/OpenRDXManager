use rdx_windows_native::VolumeLeaseSet;

fn copy_pinned_volumes(leases: VolumeLeaseSet<'_>) {
    let _copy = leases.clone();
}

fn main() {}
