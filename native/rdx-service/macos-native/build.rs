// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::env;
use std::path::PathBuf;

/// Compiles the target-gated C ownership bridge and links only Apple system frameworks.
fn main() {
    let bridge = PathBuf::from("../native/macos");
    for file in [
        "rdx_iokit.h",
        "rdx_iokit_internal.h",
        "rdx_iokit.c",
        "rdx_iokit_discovery.c",
        "rdx_iokit_prefilter.c",
        "rdx_iokit_revalidate.c",
        "rdx_iokit_scsi.c",
        "rdx_serial_contract.inc",
        "rdx_manufacturing_contract.inc",
        "rdx_serial_tests.inc",
        "rdx_iokit_acquisition_diagnostics.c",
        "rdx_iokit_da.c",
        "rdx_iokit_da_fallback.inc",
        "rdx_iokit_da_tests.inc",
        "rdx_iokit_disk.c",
        "rdx_iokit_disk_volume.inc",
        "rdx_iokit_disk_identity.inc",
        "rdx_iokit_disk_test.inc",
        "rdx_iokit_authority.c",
        "rdx_iokit_format.c",
        "rdx_iokit_gpt.c",
        "rdx_iokit_test.c",
        "rdx_iokit_usb_identity.c",
        "rdx_migration_usb.h",
        "rdx_migration_usb.c",
        "rdx_usb_bot.c",
        "rdx_usb_host.m",
        "rdx_usb_rom.h",
        "rdx_usb_rom_internal.h",
        "rdx_usb_rom.m",
        "rdx_usb_rom_inventory.m",
        "rdx_iokit_system_format.m",
        "rdx_endpoint.c",
        "rdx_endpoint_identity.c",
        "rdx_endpoint_identity.h",
    ] {
        println!("cargo:rerun-if-changed={}", bridge.join(file).display());
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let mut build = cc::Build::new();
    build
        .include(&bridge)
        .file(bridge.join("rdx_iokit.c"))
        .file(bridge.join("rdx_iokit_discovery.c"))
        .file(bridge.join("rdx_iokit_prefilter.c"))
        .file(bridge.join("rdx_iokit_revalidate.c"))
        .file(bridge.join("rdx_iokit_scsi.c"))
        .file(bridge.join("rdx_iokit_acquisition_diagnostics.c"))
        .file(bridge.join("rdx_iokit_da.c"))
        .file(bridge.join("rdx_iokit_disk.c"))
        .file(bridge.join("rdx_iokit_authority.c"))
        .file(bridge.join("rdx_iokit_format.c"))
        .file(bridge.join("rdx_iokit_gpt.c"))
        .file(bridge.join("rdx_iokit_test.c"))
        .file(bridge.join("rdx_iokit_usb_identity.c"))
        .file(bridge.join("rdx_migration_usb.c"))
        .file(bridge.join("rdx_usb_bot.c"))
        .file(bridge.join("rdx_endpoint.c"))
        .file(bridge.join("rdx_endpoint_identity.c"))
        .std("c17")
        .warnings(true)
        .extra_warnings(true)
        .flag_if_supported("-Werror")
        .flag_if_supported("-Wpedantic")
        .flag_if_supported("-fstack-protector-strong");
    if env::var_os("CARGO_FEATURE_TEST_HOOKS").is_some() {
        build.define("RDX_MACOS_TEST_HOOKS", "1");
    }
    build.compile("rdx_macos_bridge");

    let mut objc = cc::Build::new();
    objc.include(&bridge)
        .file(bridge.join("rdx_usb_host.m"))
        .file(bridge.join("rdx_usb_rom.m"))
        .file(bridge.join("rdx_usb_rom_inventory.m"))
        .file(bridge.join("rdx_iokit_system_format.m"))
        .warnings(true)
        .extra_warnings(true)
        .flag_if_supported("-Werror")
        .flag_if_supported("-Wpedantic")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .flag_if_supported("-fstack-protector-strong");
    if env::var_os("CARGO_FEATURE_TEST_HOOKS").is_some() {
        objc.define("RDX_MACOS_TEST_HOOKS", "1");
    }
    objc.compile("rdx_macos_usb_host");

    println!("cargo:rustc-link-lib=bsm");
    for framework in [
        "CoreFoundation",
        "Foundation",
        "IOKit",
        "IOUSBHost",
        "DiskArbitration",
        "Security",
    ] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
