// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/theparanoids/pam-ysshca/conf"
	"github.com/theparanoids/pam-ysshca/msg"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func Test_authenticator_authStaticKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		getTestData func(*testing.T) (ssh.PublicKey, agent.Agent, conf.Config)
	}{
		{
			name: "happy path",
			getTestData: func(*testing.T) (ssh.PublicKey, agent.Agent, conf.Config) {
				// Generate a testing key and insert into ssh agent.
				sshAgent := agent.NewKeyring()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				if err := sshAgent.Add(agent.AddedKey{PrivateKey: privKey}); err != nil {
					t.Fatal(err)
				}

				// Customize config file for tests.
				staticKeysFile, err := os.CreateTemp(t.TempDir(), "statickeys")
				if err != nil {
					t.Fatal(err)
				}

				pubKey := privKey.Public()
				p, err := ssh.NewPublicKey(pubKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(staticKeysFile.Name(), ssh.MarshalAuthorizedKey(p), 0644); err != nil {
					t.Fatal(err)
				}
				return p, sshAgent, conf.Config{
					AllowStaticKeys: true,
					StaticKeys:      []string{staticKeysFile.Name()},
				}
			},
		},
		{
			name: "no valid keys",
			getTestData: func(*testing.T) (ssh.PublicKey, agent.Agent, conf.Config) {
				// Generate a testing key and insert into ssh agent.
				sshAgent := agent.NewKeyring()
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				if err := sshAgent.Add(agent.AddedKey{PrivateKey: privKey}); err != nil {
					t.Fatal(err)
				}

				// Customize config file for tests.
				staticKeysFile, err := os.CreateTemp(t.TempDir(), "statickeys")
				if err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(staticKeysFile.Name(), []byte("no valid keys in static keys file"), 0644); err != nil {
					t.Fatal(err)
				}
				return nil, sshAgent, conf.Config{
					AllowStaticKeys: true,
					StaticKeys:      []string{staticKeysFile.Name()},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantedPubtKey, agent, conf := tt.getTestData(t)
			identities, err := getIdentitiesFromSSHAgent(agent)
			if err != nil {
				t.Fatal(err)
			}
			a := authenticator{config: &conf}
			got := a.authStaticKey(agent, identities)
			if wantedPubtKey == nil && got != nil {
				t.Errorf("authStaticKey() = %s, want nil", ssh.MarshalAuthorizedKey(got))
			}
			if wantedPubtKey != nil {
				if got == nil {
					t.Errorf("authStaticKey() should not be nil")
				}
				if !reflect.DeepEqual(ssh.MarshalAuthorizedKey(got), ssh.MarshalAuthorizedKey(wantedPubtKey)) {
					t.Errorf("authStaticKey() = %s, want %s", ssh.MarshalAuthorizedKey(got), ssh.MarshalAuthorizedKey(wantedPubtKey))
				}
			}
		})
	}
}

func Test_authenticator_authCertificate(t *testing.T) {
	t.Parallel()
	msg.SetDebugMode(true)
	tests := []struct {
		name        string
		getTestData func(*testing.T) (string, *ssh.Certificate, agent.Agent, conf.Config)
	}{
		{
			name: "happy path",
			getTestData: func(t *testing.T) (string, *ssh.Certificate, agent.Agent, conf.Config) {
				sshAgent := agent.NewKeyring()
				caSignkey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(t)
				}
				caSigner, err := ssh.NewSignerFromKey(caSignkey)
				if err != nil {
					t.Fatal(t)
				}

				private, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(t)
				}
				public, err := ssh.NewPublicKey(private.Public())
				if err != nil {
					t.Fatal(t)
				}
				cert := &ssh.Certificate{
					Key:             public,
					ValidPrincipals: []string{"valid_user"},
					ValidAfter:      uint64(time.Now().Unix() - 3600),
					ValidBefore:     uint64(time.Now().Unix() + 3600),
				}
				if err := cert.SignCert(rand.Reader, caSigner); err != nil {
					t.Fatal(err)
				}
				if err := sshAgent.Add(agent.AddedKey{PrivateKey: private, Certificate: cert}); err != nil {
					t.Fatal(err)
				}

				caKeyFile, err := os.CreateTemp(t.TempDir(), "test-ca-keys-file")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := caKeyFile.Write(ssh.MarshalAuthorizedKey(cert.SignatureKey)); err != nil {
					t.Fatal(err)
				}

				return "valid_user", cert, sshAgent, conf.Config{
					AllowCertificate: true,
					CAKeys:           []string{caKeyFile.Name()},
				}
			},
		},
		{
			name: "cert signed by invalid CA should fail",
			getTestData: func(t *testing.T) (string, *ssh.Certificate, agent.Agent, conf.Config) {
				sshAgent := agent.NewKeyring()
				invalidCASignkey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(t)
				}
				invalidCASigner, err := ssh.NewSignerFromKey(invalidCASignkey)
				if err != nil {
					t.Fatal(t)
				}

				private, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(t)
				}
				public, err := ssh.NewPublicKey(private.Public())
				if err != nil {
					t.Fatal(t)
				}
				cert := &ssh.Certificate{
					Key:             public,
					ValidPrincipals: []string{"cert_signed_by_invalid_ca"},
					ValidAfter:      uint64(time.Now().Unix() - 3600),
					ValidBefore:     uint64(time.Now().Unix() + 3600),
				}
				if err := cert.SignCert(rand.Reader, invalidCASigner); err != nil {
					t.Fatal(err)
				}
				if err := sshAgent.Add(agent.AddedKey{PrivateKey: private, Certificate: cert}); err != nil {
					t.Fatal(err)
				}

				caKeyFile, err := os.CreateTemp(t.TempDir(), "test-ca-keys-file")
				if err != nil {
					t.Fatal(err)
				}
				validCAPriv, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(t)
				}
				validCAPub, err := ssh.NewPublicKey(validCAPriv.Public())
				if err != nil {
					t.Fatal(t)
				}
				if _, err := caKeyFile.Write(ssh.MarshalAuthorizedKey(validCAPub)); err != nil {
					t.Fatal(err)
				}

				return "cert_signed_by_invalid_ca", nil, sshAgent, conf.Config{
					AllowCertificate: true,
					CAKeys:           []string{caKeyFile.Name()},
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, wantedCert, agent, conf := tt.getTestData(t)
			identities, err := getIdentitiesFromSSHAgent(agent)
			if err != nil {
				t.Fatal(err)
			}
			a := authenticator{config: &conf}
			got := a.authCertificate(agent, identities, user)
			if wantedCert == nil && got != nil {
				t.Errorf("authCertificate() = %s, want nil", ssh.MarshalAuthorizedKey(got))
			}
			if wantedCert != nil {
				if got == nil {
					t.Errorf("authCertificate() should not be nil")
				}
				if !reflect.DeepEqual(ssh.MarshalAuthorizedKey(got), ssh.MarshalAuthorizedKey(wantedCert)) {
					t.Errorf("authCertificate() = %s, want %s", ssh.MarshalAuthorizedKey(got), ssh.MarshalAuthorizedKey(wantedCert))
				}
			}
		})
	}
}
