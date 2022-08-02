// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"fmt"
	"log/syslog"

	"github.com/theparanoids/pam-ysshca/conf"
	"github.com/theparanoids/pam-ysshca/cryptoauth"
	"github.com/theparanoids/pam-ysshca/filter"
	"github.com/theparanoids/pam-ysshca/pam"
	"github.com/theparanoids/pam-ysshca/sshutils/cert"
	"github.com/theparanoids/pam-ysshca/sshutils/key"
)

func init() {
	pam.AddFilter("sudo-filter-regular", &filter.SudoFilterRegular{})

	//  Set AuthenticateWithCryptoAuth as the fallback authentication function.
	pam.SetNonSSHAgentAuthN(AuthenticateWithCryptoAuth)
}

// AuthenticateWithCryptoAuth is the fallback authentication method when the ssh-agent connection fails.
func AuthenticateWithCryptoAuth(user string, config conf.Config, sysLogger *syslog.Writer) error {
	caKeys := key.GetPublicKeysFromFiles(config.CAKeys)
	if len(caKeys) == 0 {
		return fmt.Errorf("no valid ca keys from %v", config.CAKeys)
	}

	checker := cert.CreateCertChecker(caKeys)

	// TODO: Add crypto-client arguments after we opensource sshca-client.
	auth := cryptoauth.NewAuthenticator(config, "", checker)
	return auth.Authenticate(user, sysLogger)
}

// main is required in Go main package, though PAM-SSHCA will be compiled as a shared library.
func main() {}
