// Suppress the extra console window on Windows release builds. The scan spawns
// child processes (ping, arp), and without this each one would flash a console.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    local_network_diag_lib::run();
}
