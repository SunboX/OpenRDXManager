use rdx_service::platform::windows::WindowsReadiness;

fn main() {
    let _forged = WindowsReadiness::new(true, true, true, true);
}
