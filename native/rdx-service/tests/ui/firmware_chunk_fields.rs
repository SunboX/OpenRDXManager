use rdx_service::firmware::FirmwareChunk;

/// Attempts to manufacture a transfer chunk without an authorized image.
fn main() {
    let _ = FirmwareChunk {
        offset: 0,
        bytes: &[],
    };
}
