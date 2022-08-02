#!/bin/bash
# Copyright 2022 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.


# add_user.sh is used to create user `$1` with SUDO permission on destination host,
# and adds YSSHCA-defined principals at path `/etc/ssh/additional_authorized_principals/%u`.
# AuthorizedPrincipalsFile is set in OpenSSHD config (/etc/ssh/sshd_config) to enforce the host
# to accept YSSHCA certificates with principals "${USER}" and "${USER}:touch".

set -euo pipefail

USER=$1
PRINS_DIR="/etc/ssh/additional_authorized_principals/"

useradd -m "${USER}"
usermod -p "" "${USER}"
usermod -aG sudo "${USER}"

mkdir -p "${PRINS_DIR}"
cat <<EOF > ${PRINS_DIR}/${USER}
${USER}
${USER}:touch
EOF
