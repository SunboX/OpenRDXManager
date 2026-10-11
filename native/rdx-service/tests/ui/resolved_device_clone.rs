use rdx_service::platform::ResolvedDevice;

fn copy_resolution(resolved: ResolvedDevice<'_>) {
    let _copy = resolved.clone();
}

fn main() {}
