use rdx_service::firmware::{FirmwareRevision, ProductFamily};
use rdx_service::host::{DeviceInterface, FixtureDevice, SessionDevice, SessionGeneration};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision};
use rdx_service::protocol::self_test;

fn main() {
    let fixture = FixtureDevice::new(SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:no-raw-execute").unwrap(),
            revision: DiscoveryRevision::new(1).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(282).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(1).unwrap(),
    ));
    let mut session = fixture.open();
    let _ = session.execute(&self_test());
}
