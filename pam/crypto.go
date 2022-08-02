// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"bytes"
	"crypto/sha256"
	"strings"

	"github.com/theparanoids/pam-ysshca/msg"
	"github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type hashcode [sha256.Size]byte

func hash(key ssh.PublicKey) hashcode {
	return sha256.Sum256(key.Marshal())
}

// publicKeyMap defines a hash map for searching public keys efficiently.
type publicKeyMap map[hashcode]ssh.PublicKey

func newPublicKeyMap() publicKeyMap {
	return map[hashcode]ssh.PublicKey{}
}

// append adds a slice of keys into the public key hash map.
func (m publicKeyMap) append(keys []ssh.PublicKey) {
	for _, key := range keys {
		m[hash(key)] = key
	}
}

// load reads some public key files in OpenSSH AUTHORIZED_KEYS format.
func (m publicKeyMap) load(keyPaths []string) error {
	for _, path := range keyPaths {
		keys, _, err := key.GetPublicKeysFromFile(path)
		if err != nil {
			return err
		}
		m.append(keys)
	}
	return nil
}

// contains returns true if the given key exists in the given public key map.
func (m publicKeyMap) contains(key ssh.PublicKey) bool {
	if _, ok := m[hash(key)]; !ok {
		return false
	}
	// Use bytes.Equal to prevent hash collision
	return bytes.Equal(m[hash(key)].Marshal(), key.Marshal())
}

// getIdentitiesFromSSHAgent reads all the identities from the current
// ssh-agent and returns them in []ssh.PublicKey format.
func getIdentitiesFromSSHAgent(sshagent agent.Agent) (keys []ssh.PublicKey, err error) {
	identities, err := sshagent.List()
	if err != nil {
		return nil, err
	}
	keys = make([]ssh.PublicKey, len(identities))
	for i := range identities {
		keys[i] = identities[i]
	}
	return keys, nil
}

// matchValidPrincipal uses hash table to speed up the process to match a valid principal.
func matchValidPrincipal(cert *ssh.Certificate, principals map[string]bool) bool {
	for _, principal := range cert.ValidPrincipals {
		if principals[principal] {
			return true
		}
	}
	return false
}

// getValidStaticKeys returns all the valid static keys for the given identities.
// It traverses all the keys in the static key files, and returns the ones that match the identities.
func (a *authenticator) getValidStaticKeys(identities []ssh.PublicKey) []ssh.PublicKey {
	var authorizedKeyMap = newPublicKeyMap()
	if err := authorizedKeyMap.load(a.config.StaticKeys); err != nil {
		msg.Printlf(msg.DEBUG, "Failed to load public keys: %v", err)
		return nil
	}
	var keys = make([]ssh.PublicKey, len(identities))[:0]
	for _, identity := range identities {
		if strings.Contains(identity.Type(), "cert") {
			continue
		}
		if authorizedKeyMap.contains(identity) {
			keys = append(keys, identity)
		}
	}
	return keys
}

// getValidCertificates returns all the valid certificates for the given identities.
// NOTE: A valid certificate should not be expired and have current user
//       as a principal with a valid signature, or an authorized principal
//       that belongs to the current user with a valid signature
func (a *authenticator) getValidCertificates(identities []ssh.PublicKey, username string) []*ssh.Certificate {
	// Load all the authorized principals - username (current user),
	// username with an authorized principal prefix ($prefix$username) and additional authorized principals.
	// If parsing additional authorized principals fails due to file permissions
	// or any other reason, ignore and continue.
	principals, err := a.config.AuthorizedPrincipals(username)
	if err != nil {
		msg.Printlf(msg.WARN, "Failed parsing additional authorized principals file: %v", err)
	}

	// Load all the CA keys.
	var CAKeyMap = newPublicKeyMap()
	if err := CAKeyMap.load(a.config.CAKeys); err != nil {
		msg.Printlf(msg.WARN, "Failed to load trusted CA keys: %v", err)
		return nil
	}

	// Filter out the invalid certificates.
	var certs = make([]*ssh.Certificate, len(identities))[:0]
	for index, identity := range identities {
		msg.Printlf(msg.DEBUG, "Verify the identity %d", index)

		cert, err := key.CastSSHPublicKeyToCertificate(identity)
		if err != nil || cert == nil {
			msg.Printlf(msg.DEBUG, "Identity %d is not a certificate, ignore.", index)
			continue
		}

		// Check the signing CA of the certificate.
		if !CAKeyMap.contains(cert.SignatureKey) {
			msg.Printlf(msg.DEBUG, "Identity %d is signed by untrusted CA.", index)
			continue
		}

		// Check the valid principals efficiently using hash map.
		msg.Printlf(msg.DEBUG, "Current acceptable principals: %v", principals)
		msg.Printlf(msg.DEBUG, "Certificate principals: %v", cert.ValidPrincipals)
		if !matchValidPrincipal(cert, principals) {
			msg.Printlf(msg.DEBUG, "Identity %d does not have a valid principals, authorized prins: %v, prins from cert: %s",
				index, cert.ValidPrincipals, principals)
			continue
		}

		// As the authorized principals have been matched to the certificate,
		// skip the inefficient valid principals check in ssh.CertChecker.
		var principal string
		if len(cert.ValidPrincipals) > 0 {
			principal = cert.ValidPrincipals[0]
		}

		// Check the critical options, revocation, timestamp and
		// the signature of the certificate using ssh.CertChecker.
		checker := ssh.CertChecker{
			SupportedCriticalOptions: a.config.SupportedCriticalOptions,
		}
		if err := checker.CheckCert(principal, cert); err != nil {
			msg.Printlf(msg.DEBUG, "Identity %d is invalid: %v.", index, err)
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}
