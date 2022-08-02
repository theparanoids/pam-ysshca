// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"github.com/theparanoids/pam-ysshca/msg"
	sshagent "github.com/theparanoids/ysshra/agent/ssh"
	"github.com/theparanoids/ysshra/keyid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authStaticKey challenges all the valid keys in the given identities, and return the first authenticated key.
func (a *authenticator) authStaticKey(ag agent.Agent, identities []ssh.PublicKey) ssh.PublicKey {
	// Find all the valid static keys in identities.
	var userKeys = a.getValidStaticKeys(identities)
	msg.Printlf(msg.DEBUG, "Found %d static public keys.", len(userKeys))
	if len(userKeys) == 0 {
		msg.Printlf(msg.DEBUG, "Cannot find any static public key.")
		return nil
	}

	// Challenge static keys.
	for _, key := range userKeys {
		msg.Printlf(msg.DEBUG, "Start to challenge public key %s", ssh.MarshalAuthorizedKey(key))
		if err := sshagent.ChallengeSSHAgent(ag, key); err != nil {
			msg.Printlf(msg.DEBUG, "Challenge Failed: %v", err)
			continue
		}
		return key
	}
	return nil
}

// authCertificate challenges all the valid certificates in the given identities, and return the first authenticated certificate.
func (a *authenticator) authCertificate(ag agent.Agent, identities []ssh.PublicKey, username string) *ssh.Certificate {
	// Find all the valid certificates in identities.
	userCerts := a.getValidCertificates(identities, username)
	msg.Printlf(msg.DEBUG, "Found %d valid certificates.", len(userCerts))
	if len(userCerts) == 0 {
		msg.Printlf(msg.WARN, "Cannot find any valid certificate.")
		return nil
	}

	// Challenge the certificates signed by authorized CAs.
	for i, userCert := range userCerts {
		var challenge = sshagent.ChallengeSSHAgent
		// Decorate ChallengeSSHAgent() by adding a prompt message.
		for _, prompt := range a.config.Prompters {
			kid, err := keyid.Unmarshal(userCert.KeyId)
			if err != nil {
				msg.Printlf(msg.DEBUG, "KeyID in identity %d is not valid, skip prompter", i, err)
				continue
			}
			if !prompt.RE.MatchString(kid.GetProperty(prompt.KeyIDProperty)) {
				continue
			}
			challenge = func(ag agent.Agent, key ssh.PublicKey) error {
				msg.Printf(prompt.Message)
				defer msg.Printf("\n")
				return sshagent.ChallengeSSHAgent(ag, key)
			}
			break
		}
		// Challenge the certificate.
		msg.Printlf(msg.DEBUG, "Start to challenge public key %s", ssh.MarshalAuthorizedKey(userCert))
		if err := challenge(ag, userCert); err != nil {
			msg.Printlf(msg.WARN, "Challenge Failed: %v", err)
			continue
		}
		return userCert
	}
	return nil
}
