include ../Makefile

UNAME_S := $(shell uname -s)

AWS_LC_RS_COV_EXTRA_FEATURES := unstable

asan:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --test ecdsa_tests              --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'`  --features asan

asan-release:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --release --test basic_rsa_test           --target `rustc -vV | sed -n 's|host: ||p'`  --features asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --release --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'`  --features asan

asan-fips:
# TODO: This build target produces linker error on Mac.
# Run specific tests:
#	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --test ecdsa_tests          --target `rustc -vV | sed -n 's|host: ||p'` --no-default-features --features fips,asan
	RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --lib --bins --tests --examples --target `rustc -vV | sed -n 's|host: ||p'` --no-default-features --features fips,asan

coverage:
	cargo llvm-cov --features "${AWS_LC_RS_COV_EXTRA_FEATURES}" --no-fail-fast --fail-under-lines 95 --ignore-filename-regex "aws-lc(-fips|)-sys/*" --lcov --output-path lcov.info

coverage-fips:
	cargo llvm-cov --features "${AWS_LC_RS_COV_EXTRA_FEATURES},fips" --no-fail-fast --fail-under-lines 95 --ignore-filename-regex "aws-lc(-fips|)-sys/*" --lcov --output-path lcov.info

test:
	cargo test --all-targets --features unstable
	cargo test --release --all-targets
	cargo test --release --all-targets --features bindgen,unstable
ifeq ($(UNAME_S),Linux)
	cargo test --release --all-targets --features fips,unstable
	cargo test --no-default-features --features fips,unstable
endif
	cargo test --no-default-features --features aws-lc-sys,unstable
	cargo test --no-default-features --features aws-lc-sys,ring-sig-verify,unstable
	cargo test --no-default-features --features aws-lc-sys,ring-io,unstable
	cargo test --no-default-features --features aws-lc-sys,alloc,unstable

msrv:
	cargo msrv verify

clippy:
	cargo +nightly clippy --all-targets --features bindgen,fips,unstable -- -W clippy::all  -W clippy::pedantic

ci: format clippy msrv test coverage api-diff-pub

readme:
	cargo readme | tee README.md

mirai-install:
	rustup component add rust-src rust-std rustc-dev llvm-tools clippy rustfmt
	rustup toolchain install nightly-2023-12-30
	rm -rf ./tmp/MIRAI
	mkdir -p ./tmp/MIRAI
	git clone --depth 1 --branch v1.1.9 https://github.com/endorlabs/MIRAI.git ./tmp/MIRAI
	cd ./tmp/MIRAI && cargo install --no-default-features --locked --force --path ./checker
	rm -rf tmp/MIRAI

mirai:
	cargo +nightly-2023-12-30 mirai


.PHONY: asan asan-fips asan-release ci clippy coverage coverage-fips test msrv clippy mirai-install mirai
