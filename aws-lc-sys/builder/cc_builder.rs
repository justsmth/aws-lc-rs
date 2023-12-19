// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::OutputLibType;
use std::path::PathBuf;

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use serde::Deserialize;
use std::collections::HashMap;
#[derive(Debug, Deserialize)]
struct Config {
    #[serde(flatten)]
    object_files: HashMap<String, Vec<ObjectFile>>,
}

#[derive(Debug, Deserialize)]
struct ObjectFile {
    name: String,
    source: String,
}

static MACOS_X86_64_BUILD_CFG_STR: &str = "";
/*
include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "../mac-x86-64-build.toml"
));
*/
impl crate::Builder for CcBuilder {
    fn check_dependencies(&self) -> Result<(), String> {
        Ok(())
    }

    fn build(&self) -> Result<(), String> {
        let mut build_cfg: Config = toml::from_str(MACOS_X86_64_BUILD_CFG_STR).unwrap();

        let object_files = build_cfg.object_files.get("Object").unwrap();

        let mut cc_build = cc::Build::default();
        cc_build
            .out_dir(&self.out_dir)
            .flag("-std=c99")
            .flag("-Wno-unused-parameter")
            .cpp(false)
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
        for object_file in object_files {
            cc_build.file(self.manifest_dir.join("aws-lc").join(&object_file.source));
        }

        if let Some(prefix) = &self.build_prefix {
            cc_build
                .define("BORINGSSL_IMPLEMENTATION", "1")
                .define("BORINGSSL_PREFIX", prefix.as_str())
                .compile(format!("{}crypto", prefix.as_str()).as_str());
        } else {
            cc_build.compile("crypto");
        }
        Ok(())
    }
}
