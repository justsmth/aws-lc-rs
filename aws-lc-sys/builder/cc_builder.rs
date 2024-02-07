// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::{target, target_os, OutputLibType};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) struct CcBuilder {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    build_prefix: Option<String>,
    output_lib_type: OutputLibType,
}

use cc::Tool;
use serde::Deserialize;
use std::io::{ErrorKind, Read, Write};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::{fs, io};

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
    src_needing_preprocessor: Vec<String>,
}

fn execute_command(mut command: Command, input: String) -> Result<String, io::Error> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    let mut output = String::new();
    child.stdout.take().unwrap().read_to_string(&mut output)?;
    Ok(output)
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

    fn preprocess(&self, sources: &Vec<String>, compiler: Tool) -> Vec<PathBuf> {
        let dest_dir = self.out_dir.join("preprocessed_src");
        if let Err(e) = fs::create_dir(dest_dir.clone()) {
            if e.kind() != ErrorKind::AlreadyExists {
                panic!("Unexpected IO error: {}", e.to_string());
            }
        }
        let mut preprocessed_sources = Vec::new();
        for source in sources {
            let source_path = self.manifest_dir.join("aws-lc").join(&source);
            let source_content = fs::read_to_string(&source_path).unwrap();
            // Remove comments
            let source_content = source_content.replace("//[^\n]*", "");

            let dest_path = dest_dir.join(source_path.file_name().unwrap());
            let cflags = compiler.cflags_env();
            let flags = cflags.to_str().unwrap().split(" ");
            let mut command = compiler.to_command();
            for flag in flags {
                println!("Flag: {flag}");
                command.arg(flag);
            }
            command.args(&["-E", "-DS2N_BN_HIDE_SYMBOLS=1", "-xassembler-with-cpp"]);
            let output = execute_command(command, source_content).unwrap();
            if output.is_empty() {
                panic!("WHAT!?");
            }
            let output = output.replace(";", "\n");

            println!("Content: {}", output);
            fs::write(&dest_path, output).unwrap();
            preprocessed_sources.push(dest_path.clone());
            println!("Destination: {}", dest_path.display());
            todo!()
        }
        return preprocessed_sources;
    }

    fn include_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.manifest_dir.join("include"),
            self.manifest_dir.join("generated-include"),
            self.manifest_dir.join("aws-lc").join("include"),
            self.manifest_dir
                .join("aws-lc")
                .join("third_party")
                .join("s2n-bignum")
                .join("include"),
        ]
    }

    fn defines(&self) -> HashMap<String, String> {
        let mut defines_map = HashMap::new();
        if let Some(prefix) = &self.build_prefix {
            defines_map.insert("BORINGSSL_IMPLEMENTATION".to_string(), "1".to_string());
            defines_map.insert("BORINGSSL_PREFIX".to_string(), prefix.to_string());
        }
        defines_map
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
                .file(self.manifest_dir.join("rust_wrapper.c"));

            for flag in &lib.flags {
                cc_build.flag(flag);
            }
            for include_dir in self.include_dirs() {
                cc_build.include(include_dir);
            }
            if target_os() == "linux" {
                cc_build.define("_XOPEN_SOURCE", "700").flag("-lpthread");
            }
            for define in self.defines() {
                let key: String = define.0;
                let value: String = define.1;
                let value = if value.is_empty() {
                    None
                } else {
                    Some(value.as_str())
                };
                cc_build.define(&key, value);
            }
            for source in &lib.sources {
                cc_build.file(self.manifest_dir.join("aws-lc").join(source));
            }
            let processed_sources =
                self.preprocess(&entry.src_needing_preprocessor, cc_build.get_compiler());
            for source in processed_sources {
                cc_build.file(source);
            }

            if let Some(prefix) = &self.build_prefix {
                cc_build.compile(format!("{}_crypto", prefix.as_str()).as_str());
            } else {
                cc_build.compile(&lib.name);
            }
        }
        Ok(())
    }
}
