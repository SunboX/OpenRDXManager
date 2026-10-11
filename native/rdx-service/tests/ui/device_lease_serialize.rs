use rdx_service::platform::DeviceLease;

fn serialize_lease(lease: &DeviceLease) {
    let _serialized = serde_json::to_string(lease).unwrap();
}

fn main() {}
