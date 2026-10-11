use std::path::PathBuf;

use rdx_service::firmware::{FirmwareImage, InstallableFirmwareImage, ProductFamily};
use rdx_service::host::{
    DeviceInterface, FixtureDevice, SessionDevice, SessionGeneration,
};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision};

fn consume(_authorization: InstallableFirmwareImage) {}

fn main() {
    let fixture = FixtureDevice::new(SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:firmware-linear").unwrap(),
            revision: DiscoveryRevision::new(1).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        rdx_service::firmware::FirmwareRevision::new(282).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(1).unwrap(),
    ));
    let mut session = fixture.open();
    let path = PathBuf::from("firmware.bin");
    let image = FirmwareImage::load(path, ProductFamily::Usb3Sata3).unwrap();
    let authorization = session.authorize_firmware(image).unwrap();
    consume(authorization);
    consume(authorization);
}
