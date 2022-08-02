# Copyright 2022 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

FROM debian:sid-slim

ARG PAM_SSHCA_DEB_PATH

RUN apt-get update && \
    apt-get -y install sudo openssh-server vim

# TrustedUserCAKeys is set to `/etc/ssh/ysshca_uca` in the default pam_sshca.conf.
RUN ln -s /ssh-user/ysshca_uca /etc/ssh/ysshca_uca

COPY example/docker-debian/pam.d/sudo /etc/pam.d/sudo
COPY example/docker-debian/sshd_config /etc/ssh/sshd_config
COPY example/docker-debian/banner /etc/ssh/sshd-banner
COPY example/docker-debian/add_user.sh /etc/ssh/add_user.sh

COPY ${PAM_SSHCA_DEB_PATH} /tmp/pam_sshca.deb
RUN dpkg -i /tmp/pam_sshca.deb

RUN service ssh start
CMD ["/usr/sbin/sshd","-D"]
