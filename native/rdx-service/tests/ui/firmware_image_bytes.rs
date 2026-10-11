use rdx_service::firmware::{FirmwareImage, ProductFamily};

/// Attempts to obtain transfer bytes before installed-revision authorization.
fn main() {
    let image = FirmwareImage::load("candidate.bin", ProductFamily::Usb3Sata3).unwrap();
    let _ = image.bytes();
}
