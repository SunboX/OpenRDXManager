use rdx_service::model::{
    DeviceId, DeviceIdentity, DiscoveryRevision, OperationId, OperationKind,
};
use rdx_service::operations::{OperationGeneration, OperationOwner};

fn main() {
    let _manufactured = OperationOwner::new(
        OperationId::new("op:manufactured").unwrap(),
        OperationKind::SelfTest,
        DeviceIdentity {
            id: DeviceId::new("rdx:manufactured").unwrap(),
            revision: DiscoveryRevision::new(1).unwrap(),
        },
        OperationGeneration::new(1).unwrap(),
    );
}
