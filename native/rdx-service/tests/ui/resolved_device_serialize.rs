use rdx_service::platform::ResolvedDevice;

fn serialize_resolution(resolved: &ResolvedDevice<'_>) {
    let _serialized = serde_json::to_string(resolved).unwrap();
}

fn main() {}
