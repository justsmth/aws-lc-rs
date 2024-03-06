// Copyright (c) 2022, Google Inc.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cc_builder::CcBuilder;
use cmake_builder::CmakeBuilder;

#[cfg(any(
    feature = "bindgen",
    any(
        not(any(target_os = "macos", target_os = "linux")),
        not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86"))
    )
))]
mod bindgen;
mod cc_builder;
mod cmake_builder;

pub(crate) fn get_aws_lc_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("aws-lc").join("include")
}

pub(crate) fn get_rust_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("include")
}

pub(crate) fn get_generated_include_path(manifest_dir: &Path) -> PathBuf {
    manifest_dir.join("generated-include")
}

pub(crate) fn get_aws_lc_sys_includes_path() -> Option<Vec<PathBuf>> {
    env::var("AWS_LC_SYS_INCLUDES")
        .map(|colon_delim_paths| colon_delim_paths.split(':').map(PathBuf::from).collect())
        .ok()
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputLib {
    RustWrapper,
    Crypto,
    Ssl,
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputLibType {
    Static,
    Dynamic,
}

fn env_var_to_bool(name: &str) -> Option<bool> {
    let build_type_result = env::var(name);
    if let Ok(env_var_value) = build_type_result {
        eprintln!("{name}={env_var_value}");
        // If the environment variable is set, we ignore every other factor.
        let env_var_value = env_var_value.to_lowercase();
        if env_var_value.starts_with('0')
            || env_var_value.starts_with('n')
            || env_var_value.starts_with("off")
        {
            Some(false)
        } else {
            // Otherwise, if the variable is set, assume true
            Some(true)
        }
    } else {
        None
    }
}

impl Default for OutputLibType {
    fn default() -> Self {
        if Some(false) == env_var_to_bool("AWS_LC_SYS_STATIC") {
            // Only dynamic if the value is set and is a "negative" value
            OutputLibType::Dynamic
        } else {
            OutputLibType::Static
        }
    }
}

impl OutputLibType {
    fn rust_lib_type(&self) -> &str {
        match self {
            OutputLibType::Static => "static",
            OutputLibType::Dynamic => "dylib",
        }
    }
}

impl OutputLib {
    fn libname(self, prefix: &Option<String>) -> String {
        let name = match self {
            OutputLib::Crypto => "crypto",
            OutputLib::Ssl => "ssl",
            OutputLib::RustWrapper => "rust_wrapper",
        };
        if let Some(prefix) = prefix {
            format!("{prefix}_{name}")
        } else {
            name.to_string()
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn prefix_string() -> String {
    format!("aws_lc_{}", VERSION.to_string().replace('.', "_"))
}

#[cfg(feature = "bindgen")]
fn target_platform_prefix(name: &str) -> String {
    format!("{}_{}_{}", env::consts::OS, env::consts::ARCH, name)
}

pub(crate) struct TestCommandResult {
    #[allow(dead_code)]
    output: Box<str>,
    status: bool,
}

fn test_command(executable: &OsStr, args: &[&OsStr]) -> TestCommandResult {
    if let Ok(result) = Command::new(executable).args(args).output() {
        let output = String::from_utf8(result.stdout)
            .unwrap_or_default()
            .into_boxed_str();
        return TestCommandResult {
            output,
            status: result.status.success(),
        };
    }
    TestCommandResult {
        output: String::new().into_boxed_str(),
        status: false,
    }
}

#[cfg(any(
    feature = "bindgen",
    any(
        not(any(target_os = "macos", target_os = "linux")),
        not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86"))
    )
))]
fn generate_bindings(manifest_dir: &Path, prefix: Option<String>, bindings_path: &PathBuf) {
    let options = bindgen::BindingOptions {
        build_prefix: prefix,
        include_ssl: cfg!(feature = "ssl"),
        disable_prelude: true,
    };

    let bindings = bindgen::generate_bindings(manifest_dir, &options);

    bindings
        .write(Box::new(std::fs::File::create(bindings_path).unwrap()))
        .expect("written bindings");
}

#[cfg(feature = "bindgen")]
fn generate_src_bindings(manifest_dir: &Path, prefix: Option<String>, src_bindings_path: &Path) {
    bindgen::generate_bindings(
        manifest_dir,
        &bindgen::BindingOptions {
            build_prefix: prefix.clone(),
            include_ssl: false,
            ..Default::default()
        },
    )
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto"))))
    .expect("write bindings");

    bindgen::generate_bindings(
        manifest_dir,
        &bindgen::BindingOptions {
            build_prefix: prefix,
            include_ssl: true,
            ..Default::default()
        },
    )
    .write_to_file(src_bindings_path.join(format!("{}.rs", target_platform_prefix("crypto_ssl"))))
    .expect("write bindings");
}

fn emit_rustc_cfg(cfg: &str) {
    println!("cargo:rustc-cfg={cfg}");
}

fn target_os() -> String {
    env::var("CARGO_CFG_TARGET_OS").unwrap()
}

fn target_arch() -> String {
    env::var("CARGO_CFG_TARGET_ARCH").unwrap()
}

fn target_env() -> String {
    env::var("CARGO_CFG_TARGET_ENV").unwrap()
}

fn target_vendor() -> String {
    env::var("CARGO_CFG_TARGET_VENDOR").unwrap()
}

fn target() -> String {
    env::var("TARGET").unwrap()
}

fn get_builder(prefix: &Option<String>, manifest_dir: &Path, out_dir: &Path) -> Box<dyn Builder> {
    let cmake_builder_builder = || {
        Box::new(CmakeBuilder::new(
            manifest_dir.to_path_buf(),
            out_dir.to_path_buf(),
            prefix.clone(),
            OutputLibType::default(),
        ))
    };

    let cc_builder_builder = || {
        Box::new(CcBuilder::new(
            manifest_dir.to_path_buf(),
            out_dir.to_path_buf(),
            prefix.clone(),
            OutputLibType::default(),
        ))
    };

    if let Some(val) = env_var_to_bool("AWS_LC_SYS_CMAKE_BUILDER") {
        let builder: Box<dyn Builder> = if val {
            cmake_builder_builder()
        } else {
            cc_builder_builder()
        };
        builder.check_dependencies().unwrap();
        builder
    } else {
        let cc_builder = cc_builder_builder();
        // cc_builder not used for no-prefix builds
        if prefix.is_some() && cc_builder.check_dependencies().is_ok() {
            cc_builder
        } else {
            let cmake_builder = cmake_builder_builder();
            cmake_builder.check_dependencies().unwrap();
            cmake_builder
        }
    }
}

macro_rules! cfg_bindgen_platform {
    ($binding:ident, $os:literal, $arch:literal, $env:literal, $additional:expr) => {
        let $binding = {
            (target_os() == $os && target_arch() == $arch && target_env() == $env && $additional)
                .then(|| {
                    emit_rustc_cfg(concat!($os, "_", $arch));
                    true
                })
                .unwrap_or(false)
        };
    };
}

trait Builder {
    fn check_dependencies(&self) -> Result<(), String>;
    fn build(&self) -> Result<(), String>;
}

fn main() {
    let is_internal_no_prefix =
        env_var_to_bool("AWS_LC_SYS_INTERNAL_NO_PREFIX").unwrap_or_else(|| false);
    let is_internal_generate =
        env_var_to_bool("AWS_LC_RUST_INTERNAL_BINDGEN").unwrap_or_else(|| false);
    let mut is_bindgen_required =
        is_internal_no_prefix || is_internal_generate || cfg!(feature = "bindgen");

    let pregenerated = !is_bindgen_required || is_internal_generate;

    cfg_bindgen_platform!(linux_x86, "linux", "x86", "gnu", pregenerated);
    cfg_bindgen_platform!(linux_x86_64, "linux", "x86_64", "gnu", pregenerated);
    cfg_bindgen_platform!(linux_aarch64, "linux", "aarch64", "gnu", pregenerated);
    cfg_bindgen_platform!(macos_x86_64, "macos", "x86_64", "", pregenerated);
    cfg_bindgen_platform!(macos_aarch64, "macos", "aarch64", "", pregenerated);

    if !(linux_x86 || linux_x86_64 || linux_aarch64 || macos_x86_64 || macos_aarch64) {
        is_bindgen_required = true;
    }

    let manifest_dir = env::current_dir().unwrap();
    let manifest_dir = dunce::canonicalize(Path::new(&manifest_dir)).unwrap();
    let prefix_str = prefix_string();
    let prefix = if is_internal_no_prefix {
        None
    } else {
        Some(prefix_str)
    };
    let out_dir_str = env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(out_dir_str.as_str()).to_path_buf();
    let builder = get_builder(&prefix, &manifest_dir, &out_dir);

    #[allow(unused_assignments)]
    let mut bindings_available = false;
    if is_internal_generate {
        #[cfg(feature = "bindgen")]
        {
            let src_bindings_path = Path::new(&manifest_dir).join("src");
            generate_src_bindings(&manifest_dir, prefix, &src_bindings_path);
            bindings_available = true;
        }
    } else if is_bindgen_required {
        #[cfg(any(
            feature = "bindgen",
            any(
                not(any(target_os = "macos", target_os = "linux")),
                not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86"))
            )
        ))]
        {
            let gen_bindings_path = Path::new(&env::var("OUT_DIR").unwrap()).join("bindings.rs");
            generate_bindings(&manifest_dir, prefix, &gen_bindings_path);
            emit_rustc_cfg("use_bindgen_generated");
            bindings_available = true;
        }
    } else {
        bindings_available = true;
    }

    assert!(
        bindings_available,
        "aws-lc-sys build failed. Please enable the 'bindgen' feature on aws-lc-rs or aws-lc-sys"
    );
    builder.build().unwrap();

    println!(
        "cargo:include={}",
        setup_include_paths(&out_dir, &manifest_dir).display()
    );

    // export the artifact names
    println!("cargo:libcrypto={}_crypto", prefix_string());
    if cfg!(feature = "ssl") {
        println!("cargo:libssl={}_ssl", prefix_string());
    }

    println!("cargo:rerun-if-changed=builder/");
    println!("cargo:rerun-if-changed=aws-lc/");
    println!("cargo:rerun-if-env-changed=AWS_LC_SYS_STATIC");
    println!("cargo:rerun-if-env-changed=AWS_LC_SYS_CMAKE_BUILDER");
}

fn setup_include_paths(out_dir: &Path, manifest_dir: &Path) -> PathBuf {
    let mut include_paths = vec![
        get_rust_include_path(manifest_dir),
        get_generated_include_path(manifest_dir),
        get_aws_lc_include_path(manifest_dir),
    ];

    if let Some(extra_paths) = get_aws_lc_sys_includes_path() {
        include_paths.extend(extra_paths);
    }

    let include_dir = out_dir.join("include");
    std::fs::create_dir_all(&include_dir).unwrap();

    // iterate over all the include paths and copy them into the final output
    for path in include_paths {
        for child in std::fs::read_dir(path).into_iter().flatten().flatten() {
            if child.file_type().map_or(false, |t| t.is_file()) {
                let _ = std::fs::copy(
                    child.path(),
                    include_dir.join(child.path().file_name().unwrap()),
                );
                continue;
            }

            // prefer the earliest paths
            let options = fs_extra::dir::CopyOptions::new()
                .skip_exist(true)
                .copy_inside(true);
            let _ = fs_extra::dir::copy(child.path(), &include_dir, &options);
        }
    }

    include_dir
}
