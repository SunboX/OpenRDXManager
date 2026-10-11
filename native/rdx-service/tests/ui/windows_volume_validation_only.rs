use rdx_windows_native::VolumeLeaseSet;

fn validation_only(leases: &VolumeLeaseSet<'_>) {
    leases.revalidate_for_mutation().unwrap();
}

fn main() {}
