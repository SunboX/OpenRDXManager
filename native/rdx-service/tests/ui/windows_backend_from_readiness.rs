use rdx_service::platform::windows::{WindowsBackend, WindowsReadiness};

fn forge(readiness: WindowsReadiness) {
    let _forged = WindowsBackend::from_readiness(readiness, true);
}

fn main() {}
