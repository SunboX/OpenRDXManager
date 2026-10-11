use rdx_service::platform::windows::{
    NativeScsiCompletion, build_scsi_pass_through, convert_scsi_completion,
};
use rdx_service::protocol::{log_sense, self_test};

fn main() {
    let mutating = self_test();
    let read_packet = build_scsi_pass_through(&log_sense(0x20).unwrap()).unwrap();
    let completion = NativeScsiCompletion::device(0x08, 0, Vec::new(), 0, Vec::new());
    let _forged = convert_scsi_completion(&mutating, &read_packet, completion);
}
