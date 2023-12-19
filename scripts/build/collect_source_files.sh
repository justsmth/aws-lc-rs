#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

function usage() {
  cat <<EOF 1>&2
Usage:
  $0 [-l] [-m] [-w] [-x] [-a] [-f] [-o <output_file>] [-t <type>]

OS OPTIONS:
    -s OS   Locate source for operating system.
    -c CPU  Locate source for cpu.
    -C      Locate non-CPU-specific source files.

OUTPUT OPTIONS
    -f              Overwrite existing file if it exists.
    -o OUTPUT_FILE  Name of yaml file to output to.
    -t TYPE         Output format. Type must be "YAML" or "TOML".

EOF
  exit 1;
}

#SCRIPT_DIR="$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
AWS_LC_ROOT="${REPO_ROOT}/aws-lc-sys/aws-lc"

OS_SRC="$(uname -s)"
if [[ "${OS_SRC}" == "Darwin" ]]; then
  OS_SRC="mac"
fi
CPU_SRC="$(uname -m)"

NO_ASSEMBLY=0
OUTPUT="${REPO_ROOT}/aws-lc-sys/builder/${OS_SRC}-${CPU_SRC}"
FORMAT="toml"
FORCE=0
while getopts "s:c:Cfo:t:" arg; do
  case "$arg" in
    s)
      OS_SRC="${OPTARG}"
      ;;
    c)
      if [[ ${NO_ASSEMBLY} -eq 1 ]]; then
        echo Incompatible CPU options
        echo
        usage
      fi
      CPU_SRC="${OPTARG}"
      ;;
    C)
      if [[ -n ${CPU_SRC} ]]; then
        echo Incompatible CPU options
        echo
        usage
      fi
      NO_ASSEMBLY=1
      ;;
    f)
      FORCE=1
      ;;
    o)
      OUTPUT="${OPTARG}"
      ;;
    t)
      FORMAT="${OPTARG,,}"
      if [[ "${FORMAT}" != "yaml" &&  "${FORMAT}" != 'toml' ]]; then
        echo "Available types are YAML and TOML"
        echo
        usage
      fi
      ;;
    *)
      echo Invalid flag: $arg
      exit 1
  esac
done

if [[ -z "${OUTPUT}" ]]; then
  echo Must specify output file.
  echo
  usage
fi


ALT_EXT="${FORMAT:0:1}${FORMAT:2:2}"
if [[ "${OUTPUT}" != *.${FORMAT} && "${OUTPUT}" != *.${ALT_EXT} ]]; then
  OUTPUT="${OUTPUT}.${FORMAT}"
fi

echo "Using configuration:"
echo "  * CPU_SRC=${CPU_SRC}"
echo "  * NO_ASSEMBLY=${NO_ASSEMBLY}"
echo "  * OS_SRC=${OS_SRC}"
echo "  * OUTPUT=${OUTPUT}"
echo "  * FORMAT=${FORMAT}"
echo

if [[ ( -z "${CPU_SRC}" && ${NO_ASSEMBLY} -eq 0 ) || -z "${OS_SRC}" || -z "${OUTPUT}" ]]; then
  echo Must set options for CPU, OS and OUTPUT
  echo
  usage
fi

if [[ -e "$OUTPUT" ]]; then
  if [[ ${FORCE} -eq 0  ]]; then
    echo Cannot overwrite existing file: "${OUTPUT}"
    echo
    usage
  else
    rm -f "${OUTPUT}"
  fi
fi

if ! touch "$OUTPUT"; then
  echo Unable to write to output: "${OUTPUT}"
  echo
  usage
fi


function report_library_header() {
    if [[ ${FORMAT} == "toml" ]]; then
      printf "[[Library]]\n  name = \"%s\"\n  sources = [\n" "${1}" | tee -a "${OUTPUT}"
    else
      echo "${1}:" | tee -a "${OUTPUT}"
    fi
}

function report_object_file() {
  [ -z "" ]
}

function report_options() {
  if [[ ${FORMAT} == "toml" ]]; then
    echo "  options = \"${1}\"" | tee -a "${OUTPUT}"
  else
    echo "  options: '${1}'" | tee -a "${OUTPUT}"
  fi
}

function report_source_file() {
  echo "    \"${1}\"," | tee -a "${OUTPUT}"
}

function report_library_footer() {
  echo "]" | tee -a "${OUTPUT}"
}

function collect_library() {

  MY_LIB=$(find "${REPO_ROOT}/target/debug" -type f -name "lib*${1}.a"| grep 'aws-lc-sys' | head -n 1)

  echo "Found library: ${MY_LIB}"

  report_library_header "${1}"

  mapfile -t OBJECT_FILES < <(ar -t "${MY_LIB}" | egrep "\.o$")
  OBJ_FILE_NAMES=()
  for OBJ_FILE_NAME in "${OBJECT_FILES[@]}"; do

    OBJ_FILE_PATH=$(find "${REPO_ROOT}/target/debug" -name "${OBJ_FILE_NAME}" | grep 'aws-lc-sys' | head -n 1)
    report_object_file "${OBJ_FILE_NAME}"

    #echo DEBUG: OBJ_FILE_PATH="${OBJ_FILE_PATH}"
  ## IDENTIFY SOURCE FILES
    mapfile -t SOURCE_FILES < <(gdb -q -ex "set height 0" -ex "info sources" -ex quit "${OBJ_FILE_PATH}" 2>/dev/null |\
           egrep '^\s*$' -A 100 |\
           sed -e 's/, /\n/g' |\
           grep "${AWS_LC_ROOT}" |\
           egrep "\.(c|S)$" |\
           grep -v pqcrystals_kyber_ref_common |\
           egrep -v '.*/fipsmodule/\w*/.*\.c' |\
           sort |\
           uniq)
    SRC_FOUND=0
    #echo DEBUG: SOURCE_FILES: "${SOURCE_FILES[@]}"
    if [[ ${#SOURCE_FILES[@]} -gt 0 ]]; then
      SRC_FOUND=1
      REL_SRC_PATH="${SOURCE_FILES[0]//${AWS_LC_ROOT}\//}"
      report_source_file "${REL_SRC_PATH}"
    fi
    if [[ ${SRC_FOUND} -eq 0 ]]; then
      OBJ_FILE_SRC_NAME="${OBJ_FILE_NAME//\.o/}"
      mapfile -t OBJ_FILE_SRC_FILES < <(find "${AWS_LC_ROOT}"/crypto -type f -name "${OBJ_FILE_SRC_NAME}" | egrep "\.c$")
      if [[ -n "${OBJ_FILE_SRC_NAME}" && ${#OBJ_FILE_SRC_FILES[@]} -gt 0 ]]; then
        SRC_FOUND=1
        REL_SRC_PATH="${OBJ_FILE_SRC_FILES[0]//${AWS_LC_ROOT}\//}"
        report_source_file "${REL_SRC_PATH}"
      fi
    fi
    if [[ ${SRC_FOUND} -eq 0 ]]; then
      OBJ_FILE_SRC_NAME="${OBJ_FILE_NAME//\.o/}"
      mapfile -t OBJ_FILE_SRC_FILES < <(find "${AWS_LC_ROOT}"/generated-src -type f -name "${OBJ_FILE_SRC_NAME}" | egrep "\.c$")
      if [[ -n "${OBJ_FILE_SRC_NAME}" && ${#OBJ_FILE_SRC_FILES[@]} -gt 0 ]]; then
        SRC_FOUND=1
        REL_SRC_PATH="${OBJ_FILE_SRC_FILES[0]//${AWS_LC_ROOT}\//}"
        report_source_file "${REL_SRC_PATH}"
      fi
    fi
    if [[ ${SRC_FOUND} -eq 0 ]]; then
      OBJ_FILE_SRC_NAME="${OBJ_FILE_NAME//\.o/}"
      mapfile -t OBJ_FILE_SRC_FILES < <(find "${AWS_LC_ROOT}"/generated-src -type f -name "${OBJ_FILE_SRC_NAME}" | egrep "\.S$" | grep "${OS_SRC}" | grep "${CPU_SRC}" )
      if [[ -n "${OBJ_FILE_SRC_NAME}" && ${#OBJ_FILE_SRC_FILES[@]} -gt 0 ]]; then
        SRC_FOUND=1
        REL_SRC_PATH="${OBJ_FILE_SRC_FILES[0]//${AWS_LC_ROOT}\//}"
        report_source_file "${REL_SRC_PATH}"
      fi
    fi
    if [[ ${SRC_FOUND} -eq 0 ]]; then
      OBJ_FILE_SRC_NAME="${OBJ_FILE_NAME//\.o/}"
      mapfile -t OBJ_FILE_SRC_FILES < <(find "${AWS_LC_ROOT}"/crypto -type f -name "${OBJ_FILE_SRC_NAME}" | egrep "\.S$" )
      if [[ -n "${OBJ_FILE_SRC_NAME}" && ${#OBJ_FILE_SRC_FILES[@]} -gt 0 ]]; then
        SRC_FOUND=1
        REL_SRC_PATH="${OBJ_FILE_SRC_FILES[0]//${AWS_LC_ROOT}\//}"
        report_source_file "${REL_SRC_PATH}"
      fi
    fi
    if [[ ${SRC_FOUND} -eq 0 ]]; then
      OBJ_FILE_SRC_NAME="${OBJ_FILE_NAME//\.S\.o/}"
      CPU_FILTER="${CPU_SRC}"
      if [[ "${CPU_SRC}" == "x86_64" ]]; then
        CPU_FILTER="x86"
      fi
      mapfile -t OBJ_FILE_SRC_FILES < <(find "${AWS_LC_ROOT}"/third_party/s2n-bignum -type f -name "${OBJ_FILE_SRC_NAME}" | grep "${CPU_FILTER}")
      if [[ -n "${OBJ_FILE_SRC_NAME}" && ${#OBJ_FILE_SRC_FILES[@]} -gt 0 ]]; then
        SRC_FOUND=1
        REL_SRC_PATH="${OBJ_FILE_SRC_FILES[0]//${AWS_LC_ROOT}\//}"
        report_source_file "${REL_SRC_PATH}"
      fi
    fi
    if [[ ${SRC_FOUND} -eq 0 ]]; then
        echo Unique source file not found: "${OBJ_FILE_NAME}"
        echo
        exit 2
    fi

  done

  report_library_footer

}

collect_library "crypto"
