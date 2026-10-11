use rdx_service::platform::{CandidateDevice, CandidateMetadata};

fn main() {
    let candidate = CandidateDevice::new(
        "candidate-a",
        "/private/device/a",
        CandidateMetadata::new(None, None, None, None),
    )
    .unwrap();
    let _serialized = serde_json::to_string(&candidate).unwrap();
}
