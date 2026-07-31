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

	certChecker := cert.CreateCertChecker(caKeys)

	// Apply the same certificate filters as the ssh-agent path so the cryptoauth
	// fallback enforces identical certificate restrictions (e.g. sudo-filter-regular
	// rejecting SSH-only certificates). Without this, the fallback would accept
	// certificates the normal ssh-agent path rejects.
	var filterCheckers []cryptoauth.Checker
	for _, filterPath := range config.Filters {
		flt, err := pam.ResolveFilter(filterPath)
		if err != nil {
			return fmt.Errorf("failed to resolve filter %q: %v", filterPath, err)
		}
		filterCheckers = append(filterCheckers, filter.NewCertChecker(flt))
	}

	// TODO: Add crypto-client arguments after we opensource sshca-client.
	auth := cryptoauth.NewAuthenticator(config, "", certChecker, filterCheckers...)
	return auth.Authenticate(user, sysLogger)
}

// main is required in Go main package, though PAM-SSHCA will be compiled as a shared library.
func main() {}
