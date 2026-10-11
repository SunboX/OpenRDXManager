use rdx_windows_native::ValidatedVolumeMutationLease;

fn copy_validated_mutation_lease(lease: ValidatedVolumeMutationLease<'_>) {
    let _second_authority = lease.clone();
}

fn main() {}
