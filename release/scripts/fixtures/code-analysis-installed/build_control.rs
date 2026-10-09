//! Build-control fixture only. Never substitutes for Cppcheck or clangd.
//! Validates genuine frozen ARM outputs; does not rebuild changed source.
use std::{env, fs, path::Path};

fn main() {
    let root = env::current_dir().expect("project cwd");
    let target = env::args().nth(1).expect("verify target argv");
    assert!(
        root.join(&target).exists(),
        "target must resolve from project"
    );
    let elf = fs::read(root.join("build/firmware.elf")).expect("frozen ARM ELF");
    assert!(elf.len() > 52 && &elf[..5] == b"\x7fELF\x01");
    assert_eq!(u16::from_le_bytes([elf[18], elf[19]]), 40, "ELF is ARM");
    let map = fs::read_to_string(root.join("build/firmware.map")).expect("frozen map");
    assert!(
        map.contains("main") && map.contains("heartbeat"),
        "genuine linked units"
    );
    assert!(Path::new("build/main.o").is_file());
    println!(
        "BUILD CONTROL: frozen ELF32 ARM and linked map validated; target={target}; no rebuild"
    );
}
