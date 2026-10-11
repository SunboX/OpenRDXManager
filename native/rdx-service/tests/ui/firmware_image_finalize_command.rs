use rdx_service::firmware::{FirmwareImage, ProductFamily};

/// Attempts to obtain the final transfer command before authorization.
fn main() {
    let image = FirmwareImage::load("candidate.bin", ProductFamily::Usb3Sata3).unwrap();
    let _ = image.finalize_command();
}
