// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{target, target_os, OutputLibType};
use std::path::PathBuf;

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(rename = "Library")]
    libraries: Vec<Library>,
}

#[derive(Debug, Deserialize)]
struct Library {
    name: String,
    flags: Vec<String>,
    sources: Vec<String>,
}

impl CcBuilder {
    pub(crate) fn new(
        manifest_dir: PathBuf,
        out_dir: PathBuf,
        build_prefix: Option<String>,
        output_lib_type: OutputLibType,
    ) -> Self {
        Self {
            manifest_dir,
            out_dir,
            build_prefix,
            output_lib_type,
        }
    }
    fn target_build_config_path(&self) -> PathBuf {
        self.manifest_dir
            .join("builder")
            .join("cc")
            .join(format!("{}.toml", target()))
    }
}

impl crate::Builder for CcBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        if OutputLibType::Dynamic == self.output_lib_type {
            // https://github.com/rust-lang/cc-rs/issues/594
            return Err("CcBuilder only supports static builds".to_string());
        }

        let build_cfg_path = self.target_build_config_path();
        if !build_cfg_path.exists() {
            return Err(format!("Platform not supported: {}", target()));
        }
        Ok(())
    }

    fn build(&self) -> Result<(), String> {
        let build_cfg_path = self.target_build_config_path();
        println!("cargo:rerun-if-changed={}", build_cfg_path.display());
        let build_cfg_str = fs::read_to_string(build_cfg_path).map_err(|x| x.to_string())?;
        let build_cfg: Config = toml::from_str(&build_cfg_str).unwrap();

        let entries = build_cfg.libraries;
        for entry in &entries {
            let lib = entry;
            let mut cc_build = cc::Build::default();

            cc_build
                .out_dir(&self.out_dir)
                .flag("-std=c99")
                .flag("-Wno-unused-parameter")
                .cpp(false)
                .shared_flag(false)
                .static_flag(true)
                .include(self.manifest_dir.join("include"))
                .include(self.manifest_dir.join("generated-include"))
                .include(self.manifest_dir.join("aws-lc").join("include"))
                .include(
                    self.manifest_dir
                        .join("aws-lc")
                        .join("third_party")
                        .join("s2n-bignum")
                        .join("include"),
                )
                .file(self.manifest_dir.join("rust_wrapper.c"));
            if target_os() == "linux" {
                cc_build.define("_XOPEN_SOURCE", "700").flag("-lpthread");
            }

            for source in &lib.sources {
                cc_build.file(self.manifest_dir.join("aws-lc").join(source));
            }

            for flag in &lib.flags {
                cc_build.flag(flag);
            }

            if let Some(prefix) = &self.build_prefix {
                cc_build
                    .define("BORINGSSL_IMPLEMENTATION", "1")
                    .define("BORINGSSL_PREFIX", prefix.as_str())
                    .compile(format!("{}_crypto", prefix.as_str()).as_str());
            } else {
                cc_build.compile(&lib.name);
            }
        }
        Ok(())
    }
}
