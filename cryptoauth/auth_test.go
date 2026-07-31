// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cryptoauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/theparanoids/pam-ysshca/conf"
	"github.com/theparanoids/pam-ysshca/filter"
	"github.com/theparanoids/pam-ysshca/sshutils/cert"
	"github.com/theparanoids/ysshra/keyid"
	"golang.org/x/crypto/ssh"
)

// signUserCert signs an SSH user certificate for principal with the given KeyID usage.
func signUserCert(t *testing.T, caSigner ssh.Signer, userPub ssh.PublicKey, principal string, usage keyid.Usage) *ssh.Certificate {
	t.Helper()

	kid := keyid.New()
	kid.Principals = []string{principal}
	kid.ReqUser = principal
	kid.Usage = usage
	kid.TouchPolicy = keyid.NeverTouch
	kidStr, err := kid.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal keyid: %v", err)
	}

	c := &ssh.Certificate{
		Key:             userPub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           kidStr,
		ValidPrincipals: []string{principal},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := c.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("failed to sign cert: %v", err)
	}
	return c
}

func newCASignerAndUserKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	if err != nil {
		t.Fatalf("failed to create CA signer: %v", err)
	}

	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate user key: %v", err)
	}
	userSSHPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("failed to convert user key: %v", err)
	}
	return caSigner, userSSHPub
}

// TestValidateCertEnforcesConfiguredFilters verifies that the cryptoauth fallback
// rejects SSH-only certificates when sudo-filter-regular is wired in as an
// additional cert checker, matching the ssh-agent path. See PSECBUGS-111970.
func TestValidateCertEnforcesConfiguredFilters(t *testing.T) {
	const principal = "victim"

	caSigner, userPub := newCASignerAndUserKey(t)
	certChecker := cert.CreateCertChecker([]ssh.PublicKey{caSigner.PublicKey()})
	sudoFilter := filter.NewCertChecker(&filter.SudoFilterRegular{})

	sshOnlyCert := signUserCert(t, caSigner, userPub, principal, keyid.SSHOnlyUsage)
	allUsageCert := signUserCert(t, caSigner, userPub, principal, keyid.AllUsage)

	// Sanity check: the sudo filter itself rejects the SSH-only cert and accepts
	// the all-usage cert.
	if err := sudoFilter.CheckCert(sshOnlyCert, principal); err == nil {
		t.Fatalf("expected sudo-filter-regular to reject SSH-only certificate")
	}
	if err := sudoFilter.CheckCert(allUsageCert, principal); err != nil {
		t.Fatalf("expected sudo-filter-regular to accept all-usage certificate, got %v", err)
	}

	// With the sudo filter wired in, the fallback must reject the SSH-only cert...
	authWithFilter := NewAuthenticator(conf.Config{}, "", certChecker, sudoFilter)
	if err := authWithFilter.validateCert(sshOnlyCert, principal); err == nil {
		t.Errorf("expected validateCert to reject SSH-only cert when sudo filter is configured")
	}
	// ...while still accepting a cert with full (SSH+sudo) usage.
	if err := authWithFilter.validateCert(allUsageCert, principal); err != nil {
		t.Errorf("expected validateCert to accept all-usage cert, got %v", err)
	}

	// Without additional checkers the CA-signature check alone still passes for
	// the SSH-only cert, confirming the filter checker is what enforces the
	// usage restriction (i.e. this is the previously vulnerable behavior).
	authNoFilter := NewAuthenticator(conf.Config{}, "", certChecker)
	if err := authNoFilter.validateCert(sshOnlyCert, principal); err != nil {
		t.Errorf("expected validateCert to accept CA-signed cert without filters, got %v", err)
	}
}
