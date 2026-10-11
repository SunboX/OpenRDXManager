use rdx_service::platform::CandidateDevice;

fn expose_locator(candidate: &CandidateDevice) {
    let _raw_locator = candidate.locator();
}

fn main() {}
