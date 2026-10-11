use rdx_linux_native::ScsiOperation;

fn main() {
    let _ = ScsiOperation::from_cdb(vec![0x12, 0, 0, 0, 0xFE, 0]);
}
