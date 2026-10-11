use rdx_service::platform::ResolvedDevice;

fn expose_lease(resolved: &ResolvedDevice<'_>) {
    let _lease = resolved.lease();
}

fn main() {}
