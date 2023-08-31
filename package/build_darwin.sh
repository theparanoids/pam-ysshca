#!/bin/bash
# Copyright 2023 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
#
# Run this script to build pam_sshca.so for darwin (macOS) to
# _build/darwin/{arch}/pam_sshca.so
#

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
SOURCE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. &>/dev/null && pwd)
BUILD_DIR="$SOURCE_DIR/_build"

usage() {
  cat >&2 <<__USAGE__
$SCRIPT_NAME: compile pam_sshca.so for darwin (macOS)."

Prerequisites:
- Go (e.g. brew install go)

Usage: $SCRIPT_NAME [--os-arch {arm64 | amd64 | all}]"

  --os-arch   Architecture name. Default: all"
__USAGE__
  exit 1
}

build() {
  local arch=$1
  local output_dir="$BUILD_DIR/darwin/$arch"
  mkdir -p "$output_dir"
  local -ra build_args=(
    -v
    -o "$output_dir/pam_sshca.so"
    -buildmode=c-shared
    "$SOURCE_DIR/cmd/pam_sshca"
  )
  echo "GOARCH=$arch GOOS=darwin CGO_ENABLED=1 go build ${build_args[*]}"
  GOARCH="$arch" GOOS=darwin CGO_ENABLED=1 go build "${build_args[@]}"
}

ARCHS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --os-arch)
      if [[ $2 == all ]]; then
        ARCHS+=(amd64 arm64)
      else
        ARCHS+=("$2")
      fi
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ "${#ARCHS[@]}" == 0 ]] && ARCHS=(amd64 arm64)

for arch in "${ARCHS[@]}"; do
  build "$arch"
done
