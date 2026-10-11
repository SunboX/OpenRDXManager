use rdx_service::platform::CandidateLease;

fn serialize_lease(lease: &CandidateLease) {
    let _serialized = serde_json::to_string(lease).unwrap();
}

fn main() {}
