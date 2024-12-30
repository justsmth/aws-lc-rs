#!/usr/bin/env -S cargo +nightly -Zscript
---cargo
[dependencies]
cc = "1"
---

//use std::process::Command;
use std::env;


fn main() {
    let cc = env::var("CC").unwrap();
    println!("#### CC: '{cc}'");

    let mut cc_build = cc::Build::default();
    let mut compiler = cc_build.get_compiler();

    if compiler.is_like_msvc() {
        println!("#### MSVC");
    }
    if compiler.is_like_clang() {
        println!("#### CLANG");
    }
    if compiler.is_like_gnu() {
        println!("#### GNU");
    }
    

}
