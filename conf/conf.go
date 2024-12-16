// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/theparanoids/pam-ysshca/msg"
)

// Config is the parsed config settings in pam_sshca.conf.
type Config struct {
	// Filters are programs offering additional restrictions on public keys.
	Filters []string
	// AllowStaticKeys specifies whether PAM-SSHCA should check public keys from StaticKeys for the current user.
	AllowStaticKeys bool
	// StaticKeys specifies the file paths to authorized keys.
	// The path is either an absolute path or one relative to the current user's home directory.
	StaticKeys []string
	// AllowCertificate specifies whether PAM-SSHCA should check certificates that signed by the trust CAs in CAKeys.
	AllowCertificate bool
	// SupportedCriticalOptions lists the CriticalOptions of SSH certs that PAM-SSHCA allows.
	SupportedCriticalOptions []string
	// CAKeys specified the paths of the trust CA public keys.
	CAKeys []string
	// authorizedPrincipalPrefix is the list of prefix string that tells PAM-SSHCA to accept additional principals
	// starting with that prefix string.
	// For example, authorized principal prefix "screwdriver:" will allow PAM-SSHCA to accept the authN from
	// the screwdriver tool to assume "user" by presenting a valid cert with principal "screwdriver:user".
	authorizedPrincipalPrefix []string
	// authorizedPrincipalFiles specifies the list of additional principal name files that are accepted for authentication.
	authorizedPrincipalFiles []string
	// Prompters is the list of prompters to prompt messages to users during authentication.
	Prompters []Prompter
}

func defaultConfig() Config {
	return Config{
		AllowStaticKeys:  true,
		AllowCertificate: false,
	}
}

// Prompter prompt message to users during authentication.
type Prompter struct {
	// KeyIDProperty is the property/field in Key ID.
	// Please refer to the type `KeyID` in SSHRA repo.
	KeyIDProperty string
	// RE is the regular expression to match the key ID property.
	RE *regexp.Regexp
	// Message is the message that printed to users when the RE matches to KeyIDProperty.
	Message string
}

func newPrompter(promptStr string) (Prompter, error) {
	sep := strings.Index(promptStr, " ")
	matchCondition := strings.Split(promptStr[:sep], "=")
	re, err := regexp.Compile(matchCondition[1])
	if err != nil {
		return Prompter{}, err
	}
	return Prompter{
		KeyIDProperty: matchCondition[0],
		RE:            re,
		Message:       promptStr[sep+1:],
	}, nil
}

// AuthorizedPrincipals returns the authorized principals for the given username.
func (c *Config) AuthorizedPrincipals(username string) (principals map[string]bool, err error) {
	principals = make(map[string]bool)

	principals[username] = true
	// Add "prefix:$username" to authorizedPrincipalFiles, such as "pogo:example_user".
	for _, prefix := range c.authorizedPrincipalPrefix {
		principals[fmt.Sprintf("%s%s", prefix, username)] = true
	}

	for _, authorizedPrincipalsFile := range c.authorizedPrincipalFiles {
		data, err := os.ReadFile(authorizedPrincipalsFile)
		if err != nil {
			return principals, err
		}

		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines {
			fields := bytes.Fields(line)
			if len(fields) == 0 || strings.HasPrefix(string(fields[0]), "#") {
				continue
			}
			// Last field is the principal name.
			principal := string(fields[len(fields)-1])
			principals[principal] = true
		}
	}
	msg.Printlf(msg.DEBUG, "Authorized principals: %v", principals)
	return principals, nil
}
