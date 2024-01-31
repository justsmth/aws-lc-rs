#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
PUBLISH=0
REPO_ROOT=$(git rev-parse --show-toplevel)
CRATE_NAME=aws-lc-sys
CRATE_DIR="${REPO_ROOT}/${CRATE_NAME}"

pushd "${REPO_ROOT}"

cargo clean
AWS_LC_SYS_CMAKE_BUILDER=1 cargo build --package ${CRATE_NAME} --profile dev

LIB_CRYPTO_PATH=$(find target/debug -name "libaws_lc_0_*crypto.a")
LIB_CRYPTO_PATH="${REPO_ROOT}/${LIB_CRYPTO_PATH}"

function collect_source_files() {
    if [[ "$(uname)" =~ [Dd]arwin ]]; then
        dwarfdump --debug-info ${1} | grep DW_AT_decl_file | grep "$(pwd)" | cut -d\" -f 2 | sort | uniq
    elif [[ "$(uname)" =~ [Ll]inux ]]; then
        objdump -g "${1}" | grep DW_AT_name | grep "$(pwd)" | cut -d: -f 4 | sort | uniq
    else
        echo Unknown OS: `uname`
        exit 1
    fi
}

function find_generated_src_dir() {
    OS_NAME=`uname`
    OS_NAME="${OS_NAME,,}"
    ARCH_NAME=`uname -m`
    ARCH_NAME="${ARCH_NAME,,}"
    echo "${OS_NAME}-${ARCH_NAME}"
}

function cleanup_source_files() {
    GS_DIR=$(find_generated_src_dir)
    for FILE in ${@}; do
        FILE=$(realpath ${FILE})
        echo ${FILE} | sed -e "s/.*\/aws-lc-sys\/aws-lc\///" | sed -e "s/.*\/out\/build\/aws-lc\//generated-src\/${GS_DIR}\//"
    done
}

function process_source_files() {
    cleanup_source_files ${@} | sort | uniq
}


SOURCE_FILES=$(collect_source_files ${LIB_CRYPTO_PATH} )
PROCESSED_SRC_FILES=$(process_source_files ${SOURCE_FILES})


popd

echo
echo COMPLETE
