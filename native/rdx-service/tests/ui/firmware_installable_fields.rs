use rdx_service::firmware::{FirmwareImage, InstallableFirmwareImage, ProductFamily};

/// Attempts to manufacture the authorized type-state without its policy transition.
fn main() {
    let image = FirmwareImage::load("candidate.bin", ProductFamily::Usb3Sata3).unwrap();
    let _ = InstallableFirmwareImage { image };
}
