//! Link settings for the virtio-media KMDF skeleton.
//!
//! The workspace `.cargo/config.toml` only carries the x86_64 target flags, so the
//! kernel linking flags are emitted here instead; that keeps an ARM64 build working
//! with a plain `cargo build --target aarch64-pc-windows-msvc`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=virtio_media.inf");

    // Kernel image, not a user-mode DLL.
    for arg in [
        "/NOLOGO",
        "/NODEFAULTLIB",
        "/NXCOMPAT",
        "/DYNAMICBASE",
        "/MANIFEST:NO",
        "/DRIVER",
        "/KERNEL",
        "/SUBSYSTEM:NATIVE,10.0",
        "/VERSION:10.0",
        // KMDF: the PE entry point is the framework stub in wdfdriverentry.lib,
        // which then calls the driver's `DriverEntry`.
        "/ENTRY:FxDriverEntry",
        "/OPT:REF,ICF",
        "/MERGE:.btext=.text",
        "/MERGE:.edata=.rdata",
        "/MERGE:.rustc=.data",
    ] {
        println!("cargo:rustc-link-arg={arg}");
    }
}
