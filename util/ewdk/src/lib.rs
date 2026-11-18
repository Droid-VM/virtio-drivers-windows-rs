#![allow(unused_imports)]
#![allow(dead_code)]

//! EWDK (Enterprise WDK) layout discovery for build scripts.
//!
//! Two hosts are supported:
//!
//! * **Linux / WSL** — the EWDK ISO is mounted read-only and the Windows paths
//!   inside it are reached through a clang VFS overlay (`-vfsoverlay`).  The
//!   paths and the overlay come from `ewdk.env`, sourced through `bash` exactly
//!   like before.
//! * **Native Windows** — the ISO (or an extracted copy) is a real path, so no
//!   overlay is needed and there is no `bash` to source anything with.  Set
//!   `EWDK_ROOT` (ISO root, e.g. `E:\`) and the rest is discovered: the MSVC
//!   toolset version, the SDK version and `clang-cl`.
//!
//! The chosen layout is printed to the build log, so a failed build can be
//! diagnosed from the first lines of `cargo build -v` output.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub struct EwdkConfig {
    pub vc_tools_dir: String,
    pub win_sdk_dir: String,
    pub win_sdk_version: String,
    /// clang VFS overlay path. Empty on native Windows, where SDK paths exist.
    pub vfs_overlay: String,
    pub arch: String,
    /// clang-cl used for the C SEH stub (`util/microseh/src/stub.c`).
    pub clang_cl: String,
}

impl EwdkConfig {
    pub fn new(
        vc_tools_dir: &str,
        win_sdk_dir: &str,
        win_sdk_version: &str,
        vfs_overlay: &str,
        arch: &str,
        clang_cl: &str,
    ) -> Self {
        Self {
            vc_tools_dir: vc_tools_dir.to_string(),
            win_sdk_dir: win_sdk_dir.to_string(),
            win_sdk_version: win_sdk_version.to_string(),
            vfs_overlay: vfs_overlay.to_string(),
            arch: arch.to_string(),
            clang_cl: clang_cl.to_string(),
        }
    }

    /// True when the SDK lives behind a clang VFS overlay (Linux/WSL build).
    fn vfs(&self) -> bool {
        !self.vfs_overlay.is_empty()
    }

    fn sdk_dir(&self) -> &str {
        if self.vfs() {
            "/winsys/sdk"
        } else {
            &self.win_sdk_dir
        }
    }

    pub fn include_path(&self, mode: &str) -> String {
        format!("{}/{}/{}/{}", self.sdk_dir(), "Include", self.win_sdk_version, mode)
    }

    pub fn shared_include_path(&self) -> String {
        self.include_path("shared")
    }

    pub fn kernel_include_path(&self) -> String {
        self.include_path("km")
    }

    pub fn wdf_include_path(&self) -> String {
        format!("{}/{}", self.sdk_dir(), "Include")
    }

    pub fn user_include_path(&self) -> String {
        self.include_path("um")
    }

    pub fn kernel_lib_path(&self) -> String {
        format!("{}/{}/{}/{}/{}", self.sdk_dir(), "Lib", self.win_sdk_version, "km", self.arch)
    }

    pub fn user_lib_path(&self) -> String {
        format!("{}/{}/{}/{}/{}", self.sdk_dir(), "Lib", self.win_sdk_version, "um", self.arch)
    }

    pub fn ucrt_lib_path(&self) -> String {
        format!("{}/{}/{}/{}/{}", self.sdk_dir(), "Lib", self.win_sdk_version, "ucrt", self.arch)
    }

    pub fn wdf_lib_path(&self) -> String {
        const WDF_VERSION: &'static str = "1.27";
        format!("{}/{}/{}/{}/{}/{}", self.sdk_dir(), "Lib", "wdf", "kmdf", self.arch, WDF_VERSION)
    }

    pub fn kernel_arch_define(&self) -> &'static str {
        match self.arch.as_str() {
            "x64" => "_AMD64_",
            "arm64" => "_ARM64_",
            _ => unreachable!(),
        }
    }

    fn vfs_overlay_flag(&self) -> Option<String> {
        self.vfs().then(|| format!("-vfsoverlay{}", self.vfs_overlay))
    }
}

fn target_arch() -> &'static str {
    let target = env::var("TARGET").unwrap();

    assert!(target.contains("-windows-msvc"), "unsupported target {target}");

    if target.contains("x86_64") {
        "x64"
    } else if target.contains("aarch64") {
        "arm64"
    } else {
        panic!("The target {target} is currently not supported.");
    }
}

pub fn ewdk() -> EwdkConfig {
    let arch = target_arch();

    let ewdk_config = if cfg!(windows) {
        native_windows(arch)
    } else {
        unix_via_ewdk_env(arch)
    };

    println!("EWDK Config: {:?}", ewdk_config);

    println!("cargo:rustc-link-search=native={}", ewdk_config.kernel_lib_path());
    println!("cargo:rustc-link-search=native={}", ewdk_config.wdf_lib_path());

    // A native Windows build also links the x64 host proc-macro crates with
    // rust-lld; they need the user-mode/CRT import libraries. These directories
    // do not exist on the Linux mount, so only add the ones that are present.
    for path in [ewdk_config.user_lib_path(), ewdk_config.ucrt_lib_path()] {
        if Path::new(&path).is_dir() {
            println!("cargo:rustc-link-search=native={}", path);
        }
    }

    ewdk_config
}

/// Native Windows: `EWDK_ROOT` points at the mounted ISO (or an extracted copy).
/// `WINSDKDIR` / `VCTOOLSDIR` / `WINSDKVER` / `VCTOOLSVER` may be set explicitly
/// to override discovery; `CLANG_CL` may point at a specific clang-cl.exe.
fn native_windows(arch: &str) -> EwdkConfig {
    let root = env::var("EWDK_ROOT").ok().map(PathBuf::from);

    let win_sdk_dir = env::var("WINSDKDIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| root.as_ref().map(|root| root.join("Program Files/Windows Kits/10")))
        .unwrap_or_else(|| {
            panic!(
                "EWDK not configured: set EWDK_ROOT to the mounted EWDK ISO root \
                 (e.g. E:\\ or D:\\ewdk), or set WINSDKDIR to \
                 <EWDK_ROOT>\\Program Files\\Windows Kits\\10"
            )
        });

    let win_sdk_version = env::var("WINSDKVER").unwrap_or_else(|_| {
        newest_child(&win_sdk_dir.join("Include"))
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .unwrap_or_else(|| "10.0.26100.0".to_string())
    });

    let vc_tools_dir = env::var("VCTOOLSDIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            let root = root.as_ref()?;
            let tools = root.join(
                "Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC",
            );
            if let Ok(ver) = env::var("VCTOOLSVER") {
                Some(tools.join(ver))
            } else {
                newest_child(&tools)
            }
        })
        .unwrap_or_else(|| {
            panic!(
                "EWDK MSVC toolset not found: expected \
                 <EWDK_ROOT>\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\
                 VC\\Tools\\MSVC\\<version>; set VCTOOLSDIR explicitly if the ISO layout differs"
            )
        });

    let clang_cl = find_clang_cl(&vc_tools_dir);

    EwdkConfig::new(
        &vc_tools_dir.to_string_lossy(),
        &win_sdk_dir.to_string_lossy(),
        &win_sdk_version,
        "",
        arch,
        &clang_cl,
    )
}

/// Linux / WSL: the original behaviour — read `ewdk.env` through `bash`, with
/// `EWDK_ROOT` as an optional fallback so one environment variable is enough.
fn unix_via_ewdk_env(arch: &str) -> EwdkConfig {
    if let Some(root) = env::var_os("EWDK_ROOT") {
        let root = PathBuf::from(root);
        let sdk_dir = root.join("Program Files/Windows Kits/10");
        let sdk_ver = env::var("WINSDKVER").unwrap_or_else(|_| "10.0.26100.0".to_string());
        let tools =
            root.join("Program Files/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC");
        let vc_tools_dir = env::var("VCTOOLSDIR")
            .ok()
            .map(PathBuf::from)
            .or_else(|| newest_child(&tools))
            .unwrap_or_else(|| {
                panic!("EWDK_ROOT is set but no MSVC toolset was found under {:?}", tools)
            });
        let vfs_overlay = env::var("VFSOVERLAY").ok().unwrap_or_default();
        let clang_cl = env::var("CLANG_CL").unwrap_or_else(|_| "clang-cl".to_string());

        return EwdkConfig::new(
            &vc_tools_dir.to_string_lossy(),
            &sdk_dir.to_string_lossy(),
            &sdk_ver,
            &vfs_overlay,
            arch,
            &clang_cl,
        );
    }

    let lines: Vec<_> = Command::new("bash")
        .args([
            "-c",
            "source ../ewdk.env 2>/dev/null; source ../../ewdk.env 2>/dev/null; \
             echo $VCTOOLSDIR; echo $WINSDKDIR; echo $WINSDKVER; echo $VFSOVERLAY",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|stdout| {
            Some(
                stdout
                    .split('\n')
                    .map(String::from)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|lines: &Vec<String>| lines.len() >= 3)
        .unwrap_or_else(|| {
            panic!("EWDK not configured: create ewdk.env (see README) or export EWDK_ROOT=/mnt/ewdk")
        });

    let vc_tools_dir = lines.get(0).cloned().unwrap_or_default();
    let win_sdk_dir = lines.get(1).cloned().unwrap_or_default();
    let win_sdk_version = lines.get(2).cloned().unwrap_or_else(|| "10.0.26100.0".into());
    let vfs_overlay = lines.get(3).cloned().unwrap_or_default();
    let clang_cl = env::var("CLANG_CL").unwrap_or_else(|_| "clang-cl".to_string());

    EwdkConfig::new(&vc_tools_dir, &win_sdk_dir, &win_sdk_version, &vfs_overlay, arch, &clang_cl)
}

fn newest_child(dir: &Path) -> Option<PathBuf> {
    // Version dirs only: "Include" also holds "wdf", which sorts after
    // "10.0.26100.0" and must not be picked as the SDK version.
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    names.sort();
    names.pop().map(|name| dir.join(name))
}

/// clang-cl ships with the Visual Studio "C++ Clang tools" component.  The
/// EWDK layout keeps it next to the MSVC toolsets; fall back to `PATH`.
fn find_clang_cl(vc_tools_dir: &Path) -> String {
    if let Ok(explicit) = env::var("CLANG_CL") {
        return explicit;
    }

    if let Some(tools_dir) = vc_tools_dir.parent().and_then(|p| p.parent()) {
        for rel in ["Llvm/x64/bin/clang-cl.exe", "Llvm/bin/clang-cl.exe"] {
            let candidate = tools_dir.join(rel);
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }

    "clang-cl".to_string()
}

const DXGKDDI_INTERFACE_VERSION: &'static str = "DXGKDDI_INTERFACE_VERSION_WDDM2_0";

pub fn ewdk_cc() -> cc::Build {
    let ewdk_config = ewdk();

    let kernel_include_dir = ewdk_config.kernel_include_path();
    let shared_include_dir = ewdk_config.shared_include_path();
    let kernel_arch_define = ewdk_config.kernel_arch_define();

    let mut build = cc::Build::new();
    build
        .compiler(&ewdk_config.clang_cl)
        .flag("-Wno-nonportable-include-path")
        .flag("-Wno-ignored-attributes")
        .flag("-Wno-ignored-pragma-intrinsic")
        .flag("-Wno-deprecated-declarations")
        .flag("-Wno-pragma-pack")
        .flag("-Wno-unknown-pragmas")
        .flag("-Wno-unused-local-typedef")
        .flag("-Wno-microsoft-anon-tag")
        .flag("-Wno-macro-redefined")
        .flag("-Wno-microsoft-enum-forward-reference")
        .flag("-Wno-unused-but-set-variable")
        .flag("-Wno-visibility")
        .flag("-Wno-unused-value")
        .flag("-Wno-extra-tokens")
        .flag("-Wno-invalid-token-paste")
        .flag("-fms-compatibility")
        .flag("-fms-extensions")
        .flag(format!("-D{}={}", "DXGKDDI_INTERFACE_VERSION", DXGKDDI_INTERFACE_VERSION))
        .flag(format!("-D{}", kernel_arch_define))
        .flag(format!("-I{}", shared_include_dir))
        .flag(format!("-I{}", kernel_include_dir))
        .flag(format!("-I{}/crt", kernel_include_dir));

    if let Some(vfs_overlay) = ewdk_config.vfs_overlay_flag() {
        build.flag(vfs_overlay);
    }

    build
}

pub fn ewdk_bindgen() -> bindgen::Builder {
    let ewdk_config = ewdk();

    let wdf_include_dir = ewdk_config.wdf_include_path();
    let kernel_include_dir = ewdk_config.kernel_include_path();
    let shared_include_dir = ewdk_config.shared_include_path();
    let kernel_arch_define = ewdk_config.kernel_arch_define();

    let mut bindgen = bindgen::Builder::default()
        .clang_arg("-Wno-nonportable-include-path")
        .clang_arg("-Wno-ignored-attributes")
        .clang_arg("-Wno-ignored-pragma-intrinsic")
        .clang_arg("-Wno-deprecated-declarations")
        .clang_arg("-Wno-pragma-pack")
        .clang_arg("-Wno-visibility")
        .clang_arg("-Wno-unused-value")
        .clang_arg("-Wno-extra-tokens")
        .clang_arg("-Wno-invalid-token-paste")
        .clang_arg("-fms-compatibility")
        .clang_arg("-fms-extensions")
        .clang_arg(format!("-D{}={}", "DXGKDDI_INTERFACE_VERSION", DXGKDDI_INTERFACE_VERSION))
        .clang_arg(format!("-D{}", kernel_arch_define))
        .clang_arg(format!("-I{}", shared_include_dir))
        .clang_arg(format!("-I{}", kernel_include_dir))
        .clang_arg(format!("-I{}", wdf_include_dir))
        .clang_arg(format!("-I{}/crt", kernel_include_dir));

    if let Some(vfs_overlay) = ewdk_config.vfs_overlay_flag() {
        bindgen = bindgen.clang_arg(vfs_overlay);
    }

    bindgen.parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
}
