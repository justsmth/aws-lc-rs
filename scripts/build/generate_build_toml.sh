#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -e

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PUBLISH=0
REPO_ROOT=$(git rev-parse --show-toplevel)
SYS_CRATE_DIR="${REPO_ROOT}/aws-lc-sys"
BUILD_CFG_DIR="${SYS_CRATE_DIR}/builder/cc"

function collect_source_files() {
    OS_NAME=$(uname)
    if [[ "${OS_NAME}" =~ [Dd]arwin ]]; then
        dwarfdump --debug-info "${1}" | grep DW_AT_name | grep "$(pwd)" | cut -d\" -f 2 | sort | uniq
    elif [[ "${OS_NAME}" =~ [Ll]inux ]]; then
        objdump -g "${1}" | grep DW_AT_name | grep "$(pwd)" | cut -d: -f 4 | sort | uniq
    else
        echo Unknown OS: "${OS_NAME}"
        exit 1
    fi
}

function find_s2n_bignum_src_dir() {
    ARCH_NAME=$(uname -m)
    if [[ "${ARCH_NAME}" =~ x86 ]]; then
        echo x86_att
    else
        echo arm
    fi
}

function find_generated_src_dir() {
    OS_NAME=$(uname)
    if [[ "${OS_NAME}" =~ [Dd]arwin ]]; then
        OS_NAME=mac
    elif [[ "${OS_NAME}" =~ [Ll]inux ]]; then
        OS_NAME=linux
    else
        echo Unknown OS: "${OS_NAME}"
        exit 1
    fi
    ARCH_NAME=$(uname -m)
    echo "${OS_NAME}-${ARCH_NAME}"
}

function cleanup_source_files() {
    GS_DIR=$(find_generated_src_dir)
    S2N_BN_DIR=$(find_s2n_bignum_src_dir)
    for FILE in "${@}"; do
        if [[ -n "${FILE}" ]]; then
            FILE=$(realpath "${FILE}")
            echo "${FILE}" | \
                sed -e "s/.*\/aws-lc-sys\/aws-lc\///" | \
                sed -e "s/.*\/out\/build\/aws-lc\/crypto\/fipsmodule\/\(.*\.S\)\.S$/third_party\/s2n-bignum\/${S2N_BN_DIR}\/\1/" | \
                sed -e "s/.*\/out\/build\/aws-lc\//generated-src\/${GS_DIR}\//" | \
                sed -e 's/\(.*\)\/[^\/]*\/crypto\/err_data\.c/\1\/err_data.c/'
        fi
    done
}

function process_source_files() {
    cleanup_source_files "${@}" | sort | uniq
}

function verify_source_files() {
    for FILE in "${@}"; do
        FILE_PATH="${SYS_CRATE_DIR}/aws-lc/${FILE}"
        if [[ ! -f "${FILE_PATH}" ]]; then
            echo File does not exist: "${FILE_PATH}"
            exit 1
        fi
    done
}

function generate_toml() {
    cat << EOF
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC
#
# Generated-by: ${BASH_SOURCE[0]}

[[Library]]
name = "crypto"
flags = []
sources = [
EOF
    for FILE in "${@}"; do
        echo "    \"${FILE}\","
    done
    echo "]"

}

pushd "${REPO_ROOT}"

cargo clean
AWS_LC_SYS_CMAKE_BUILDER=1 AWS_LC_SYS_CC_TOML_GENERATOR=1 cargo build --package aws-lc-sys --profile dev

LIB_CRYPTO_PATH=$(find target/debug -name "libaws_lc_0_*crypto.a"| head -n 1)
LIB_CRYPTO_PATH="${REPO_ROOT}/${LIB_CRYPTO_PATH}"

SOURCE_FILES=($(collect_source_files "${LIB_CRYPTO_PATH}"))
PROCESSED_SRC_FILES=($(process_source_files "${SOURCE_FILES[@]}"))

verify_source_files "${PROCESSED_SRC_FILES[@]}"

RUST_TRIPLE=$(rustc -vV | grep host | sed -e 's/host: *\(\w*\)/\1/')
BUILD_CFG_PATH="${BUILD_CFG_DIR}/${RUST_TRIPLE}.toml"

generate_toml ${PROCESSED_SRC_FILES[@]} > ${BUILD_CFG_PATH}

echo
echo Build configuration written to: ${BUILD_CFG_PATH}
echo

cargo clean
AWS_LC_SYS_CMAKE_BUILDER=0 cargo build --package aws-lc-sys --profile dev
AWS_LC_SYS_CMAKE_BUILDER=0 cargo test --package aws-lc-rs --profile dev

popd

echo
echo COMPLETE
