#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    ui_shell::launch_desktop();
}
