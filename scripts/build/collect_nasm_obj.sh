#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

set -ex
set -o pipefail

if [[ ${BASH_VERSINFO[0]} -lt 4 ]]; then
    echo Must use bash 4 or later: ${BASH_VERSION}
    exit 1
fi

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
REPO_ROOT=$(git rev-parse --show-toplevel)
SYS_CRATE_DIR="${REPO_ROOT}/aws-lc-sys"
PREBUILT_NASM_DIR="${SYS_CRATE_DIR}/builder/prebuilt-nasm"
mkdir -p "${PREBUILT_NASM_DIR}"
rm -f "${PREBUILT_NASM_DIR}"/*

for nasm_file in `find aws-lc-sys/aws-lc/generated-src/win-x86_64/ -name "*.asm"`; do
  OBJNAME=$(basename "${nasm_file}");
  NASM_OBJ=$(find target/debug/build/ -name "${OBJNAME/.asm/.obj}");
  cp "${NASM_OBJ}" "${PREBUILT_NASM_DIR}"
done
