use rdx_service::platform::{CandidateDevice, CandidateMetadata};

fn main() {
    let candidate = CandidateDevice::new(
        "candidate-a",
        "/private/device/a",
        CandidateMetadata::new(None, None, None, None),
    )
    .unwrap();
    let _copy = candidate.clone();
}
