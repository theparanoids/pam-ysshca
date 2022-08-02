#!/bin/bash
# Copyright 2022 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

set -euo pipefail

PAM_SSHCA_DIR="/pam_sshca"
TEMPROOT="/tmp/pam_sshca_deb"
BUILD_DIR="${PAM_SSHCA_DIR}/_build"
GITHUB_URL="http://theparanoids.com/"

helper_message() {
    cat <<EOF
$(basename $0): Compile PAM_SSHCA and package it into rpm or deb in Debian env.

Prerequisites:
- Go
- Ruby and fpm package

Usage:
    --package-type)
      PACKAGE_TYPE=$2
      shift
      shift
    ;;
    --package-name)
      PACKAGE_NAME=$2
      shift
      shift
    ;;
    --package-version)
      PACKAGE_VERSION=$2
      shift
      shift
    ;;
    --os-arch)
      OS_ARCH=$2
      shift
      shift

  --package-type    (Optional) The package type to package (all, deb, rpm). Default: all
  --package-name    (Optional) The package name to output. Default: pam-sshca
  --package-version (Optional) The version of the package. Default: 0.0.1
  --os-arch         (Optional) The architecture name. Usually matches 'uname -m'. Default: amd64
  --iteration       (Optional) Number of the iteration. Default: 1
EOF
}

populate() {
  : "${PACKAGE_NAME:=pam-sshca}"
  : "${PACKAGE_VERSION:=0.0.1}"
  : "${OS_ARCH:=amd64}"
  : "${PACKAGE_TYPE:=all}"
  : "${ITERATION:=1}"
}

install_dependency() {
  echo "***** Install required packages *****"
  apt-get update
  apt-get install -y libpam-dev
  apt-get install -y ruby ruby-dev rubygems build-essential
  gem install fpm
}

compile() {
  echo "***** Compile PAM_SSHCA shared library *****"

  # Disable StrictHostKeyChecking in case `go build` requires ssh access to Github.
  cat <<EOF >> /etc/ssh/ssh_config
  Host *
      StrictHostKeyChecking no
EOF

  cd ${PAM_SSHCA_DIR}
  mkdir -p ${BUILD_DIR}
  GOARCH=amd64 go build -v -o ${BUILD_DIR}/pam_sshca.so -buildmode=c-shared ${PAM_SSHCA_DIR}/cmd/pam_sshca
}

prepare_files() {
  echo "***** Prepare files for packaging *****"

  mkdir -p ${TEMPROOT}
  install --mode=0644 -o root -D /pam_sshca/package/pam_sshca.conf ${TEMPROOT}/etc/pam_sshca.conf
  install --mode=0755 -o root -D ${BUILD_DIR}/pam_sshca.so ${TEMPROOT}/lib/security/pam_sshca.so
  install --mode=0755 -o root -D ${BUILD_DIR}/pam_sshca.so ${TEMPROOT}/lib64/security/pam_sshca.so
}

package_deb() {
  echo "***** Packaging .deb *****"

  fpm -s dir -t deb \
    -n "${PACKAGE_NAME}" \
    -v "${PACKAGE_VERSION}" \
    -a "${OS_ARCH}" -C "${TEMPROOT}" \
    --license apache2.0 \
    --force \
    --no-deb-auto-config-files \
    --deb-no-default-config-files \
    --url ${GITHUB_URL} \
    --iteration ${ITERATION} \
    --description "${PACKAGE_NAME}"

  dpkg --contents *.deb
  mv *.deb ${BUILD_DIR}
}

package_rpm() {
  echo "***** Packaging .rpm *****"

  apt-get install -y rpm

  fpm -s dir -t rpm \
    -n "${PACKAGE_NAME}" \
    -v "${PACKAGE_VERSION}" \
    -a "${OS_ARCH}" -C "${TEMPROOT}" \
    --license apache2.0 \
    --force \
    --url ${GITHUB_URL} \
    --iteration ${ITERATION} \
    --description "${PACKAGE_NAME}"

  rpm -qlp *.rpm
  mv *.rpm ${BUILD_DIR}
}

summary() {
  echo "***** Summarize ${BUILD_DIR} *****"
  ls -l ${BUILD_DIR}
}


main() {
  install_dependency
  populate
  compile
  prepare_files
  if [[ ${PACKAGE_TYPE} == "deb" || ${PACKAGE_TYPE} == "all" ]]; then
    package_deb
  fi
  if [[ ${PACKAGE_TYPE} == "rpm" || ${PACKAGE_TYPE} == "all" ]]; then
    package_rpm
  fi
  summary
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --package-type)
      PACKAGE_TYPE=$2
      shift
      shift
    ;;
    --package-name)
      PACKAGE_NAME=$2
      shift
      shift
    ;;
    --package-version)
      PACKAGE_VERSION=$2
      shift
      shift
    ;;
    --os-arch)
      OS_ARCH=$2
      shift
      shift
    ;;
    --iteration)
      ITERATION=$2
      shift
      shift
    ;;
    -h|--help)
      helper_message
      exit 0
    ;;
    *)
      helper_message
      exit 1
    ;;
  esac
done

main
