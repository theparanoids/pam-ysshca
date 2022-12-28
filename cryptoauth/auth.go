// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cryptoauth

import (
	"fmt"
	"log/syslog"

	"github.com/theparanoids/pam-ysshca/conf"
	"github.com/theparanoids/pam-ysshca/msg"
	"github.com/theparanoids/pam-ysshca/sshutils/challenge"
	"github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
)

const (
	clientCommandPrompt     = "No working ssh-agent connection found. If this is expected, please authenticate manually by running the following command in a terminal window on your client computer and pasting the resulting output here:"
	clientCommand           = "cryptoauth-client %s"
	challengePrompt         = "Please copy the following data and paste it in client's window to start authentication."
	challengeResponsePrompt = "Paste signed response from client: "
)

// checker is the interface to check whether an SSH certificate is valid or not.
// Caller can add additional cert checkers into the Authenticator.
type checker interface {
	CheckCert(cert *ssh.Certificate, principal string) error
}

// Authenticator is the struct to perform ASCII Crypto Challenge with users without accessing ssh-agent.
type Authenticator struct {
	*ssh.CertChecker
	prompter               *msg.Prompter
	clientArgs             string
	additionalCertCheckers []checker
	userCAKeysFiles        []string
}

// NewAuthenticator returns a new Authenticator.
func NewAuthenticator(config conf.Config, clientArgs string, certChecker *ssh.CertChecker, additionalCertCheckers ...checker) *Authenticator {
	auth := &Authenticator{
		CertChecker:            certChecker,
		prompter:               msg.NewPrompter(),
		clientArgs:             clientArgs,
		userCAKeysFiles:        config.CAKeys,
		additionalCertCheckers: additionalCertCheckers,
	}
	return auth
}

// Authenticate performs the authentication for the principal.
func (a *Authenticator) Authenticate(principal string, syslogger *syslog.Writer) error {
	cert, err := a.readCert()
	if err != nil {
		return err
	}
	if err := a.validateCert(cert, principal); err != nil {
		return fmt.Errorf("certificate validation failed, err: %v", err)
	}
	msg.Printf("\ncertificate verified\n")

	ch, err := challenge.NewChallenge(cert)
	if err != nil {
		return fmt.Errorf("failed to generate Challenge, err: %v", err)
	}
	cReq, err := ch.ChallengeRequest()
	if err != nil {
		return fmt.Errorf("failed to generate Challenge data, err: %v", err)
	}

	a.prompter.Promptf("%s\n%s\n", challengePrompt, cReq)
	a.prompter.Prompt(challengeResponsePrompt)

	cResp, err := a.prompter.ReadString()
	if err != nil {
		return err
	}
	if err := ch.VerifyResponse(cResp); err != nil {
		return fmt.Errorf("failed to verify Challenge")
	}
	msg.Printf("\nauthentication successful.\n")
	if syslogger != nil {
		if err := syslogger.Info(fmt.Sprintf("Grant: USER=%s, KEYID=(%s)", principal, cert.KeyId)); err != nil {
			return fmt.Errorf("syslog write failed, err: %v", err)
		}
	}
	return nil
}

func (a *Authenticator) readCert() (*ssh.Certificate, error) {
	clientCmd := fmt.Sprintf(clientCommand, a.clientArgs)
	a.prompter.Promptf("%s\n\n\t%s\n", clientCommandPrompt, clientCmd)
	certStr, err := a.prompter.ReadString()
	if err != nil {
		return nil, err
	}
	keys, _, err := key.GetPublicKeysFromBytes([]byte(certStr))
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates, err: %v", err)
	}

	cert, err := key.CastSSHPublicKeyToCertificate(keys[0])
	if err != nil {
		return nil, fmt.Errorf("failed to cast public key to Certificate, err: %v", err)
	}
	return cert, nil
}

// validateCert validates certificate signed by crypki servers.
// For validation to succeed the certificate must be
// - all the additional cert checkers pass the check.
// - the ssh cert checker pass the check.
// - the signature key matches to the user authority.
func (a *Authenticator) validateCert(cert *ssh.Certificate, principal string) error {
	for _, checker := range a.additionalCertCheckers {
		if err := checker.CheckCert(cert, principal); err != nil {
			return fmt.Errorf("certificate check failed, err: %v", err)
		}
	}

	// Validate revocation, timestamp, validPrincipals,  and
	// the signature of the certificate.
	if err := a.CertChecker.CheckCert(principal, cert); err != nil {
		return err
	}
	// Verify if the certificate is indeed signed by the CA.
	if !a.CertChecker.IsUserAuthority(cert.SignatureKey) {
		return fmt.Errorf("certificate signed by unrecognized authority")
	}
	return nil
}
