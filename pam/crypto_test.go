// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"strconv"
	"testing"
	"time"

	"github.com/theparanoids/pam-ysshca/conf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testKeys(t *testing.T) []agent.AddedKey {
	var addedKeys []agent.AddedKey
	for i := 0; i < 10; i++ {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			continue
		}
		addedKeys = append(addedKeys, agent.AddedKey{PrivateKey: private})
	}
	return addedKeys
}

func testCerts(t *testing.T) []agent.AddedKey {
	signkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(t)
	}
	signer, err := ssh.NewSignerFromKey(signkey)
	if err != nil {
		t.Fatal(t)
	}

	var addedCerts []agent.AddedKey
	for i := int64(0); i < 10; i++ {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			continue
		}
		public, err := ssh.NewPublicKey(private.Public())
		if err != nil {
			continue
		}
		cert := &ssh.Certificate{
			Key:             public,
			ValidPrincipals: []string{fmt.Sprintf("%d", i)},
			ValidAfter:      uint64(time.Now().Unix() + (i-4)*3600),
			ValidBefore:     uint64(time.Now().Unix() + (i-3)*3600),
		}
		if err := cert.SignCert(rand.Reader, signer); err != nil {
			t.Fatal(err)
		}
		addedCerts = append(addedCerts, agent.AddedKey{PrivateKey: private, Certificate: cert})
	}

	return addedCerts
}

func addKeys(t *testing.T, sshAgent agent.Agent, addedKeys []agent.AddedKey) {
	for _, key := range addedKeys {
		if err := sshAgent.Add(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGetIdentitiesFromSSHAgent(t *testing.T) {
	t.Parallel()
	sshAgent := agent.NewKeyring()
	keys := testKeys(t)
	addKeys(t, sshAgent, keys)

	identities, err := getIdentitiesFromSSHAgent(sshAgent)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != len(keys) {
		t.Fatalf("failed to get all the keys in ssh-agent")
	}
	for i := 0; i < len(identities); i++ {
		public, err := ssh.NewPublicKey(keys[i].PrivateKey.(*rsa.PrivateKey).Public())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(public.Marshal(), identities[i].Marshal()) {
			t.Logf("Expected: %v", public.Marshal())
			t.Logf("Actual: %v", identities[i].Marshal())
			t.Fatalf("failed to get identities in ssh-agent")
		}
	}
}

func TestGetValidStaticKeys(t *testing.T) {
	t.Parallel()
	// Customize config file for tests.
	tmp, err := ioutil.TempFile(t.TempDir(), "statickeys")
	if err != nil {
		t.Fatal(err)
	}

	// Generate testing keys.
	sshagent := agent.NewKeyring()
	fakeKeys := testKeys(t)
	addKeys(t, sshagent, fakeKeys)

	out := ""
	// Randomly added indexes between 1-10.
	randomIndexes := []int{2, 5, 8}
	for _, index := range randomIndexes {
		publicKey := fakeKeys[index].PrivateKey.(*rsa.PrivateKey).Public()
		// get public key
		p, err := ssh.NewPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		out += fmt.Sprint(string(ssh.MarshalAuthorizedKey(p)))
	}
	// Write keys to the static key file.
	if err := ioutil.WriteFile(tmp.Name(), []byte(out), 0644); err != nil {
		t.Fatal(err)
	}
	// Get all identities from the current ssh-agent.
	identities, err := getIdentitiesFromSSHAgent(sshagent)
	if err != nil {
		t.Fatal(err)
	}

	a := &authenticator{
		config: &conf.Config{
			AllowStaticKeys: true,
			StaticKeys:      []string{tmp.Name()},
		},
	}

	pubkeys := a.getValidStaticKeys(identities)
	if got, want := len(pubkeys), len(randomIndexes); got != want {
		t.Errorf("mismatch in number of valid static keys, gotKeys %v, wantKeys %v", got, want)
	}
	gotKeys := ""
	for _, id := range pubkeys {
		gotKeys += fmt.Sprintln(id)
	}
	wantKeys, err := ioutil.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal([]byte(gotKeys), wantKeys) {
		t.Errorf("Output doesn't match\ngot: %v\nwant: %v", gotKeys, string(wantKeys))
	}
}

func TestGetInvalidStaticKeys(t *testing.T) {
	t.Parallel()
	sshagent := agent.NewKeyring()
	fakeCerts := testCerts(t)
	addKeys(t, sshagent, fakeCerts)

	// Add a keypair with doesn't match to the keys in the static keys file.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshagent.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}

	identities, err := getIdentitiesFromSSHAgent(sshagent)
	if err != nil {
		t.Fatal(err)
	}

	a := &authenticator{
		config: &conf.Config{
			AllowStaticKeys: true,
		},
	}

	// No valid static key, should return empty slice.
	if pubKeys := a.getValidStaticKeys(identities); len(pubKeys) != 0 {
		t.Fatalf("Expected no valid static key(s), got: %v", len(pubKeys))
	}
	// Set invalid static key file path, should return empty slice.
	a.config.StaticKeys = append(a.config.StaticKeys, "invalid-path.txt")
	if pubKeys := a.getValidStaticKeys(identities); len(pubKeys) != 0 {
		t.Fatalf("Expected no valid static key(s) for invalid file path")
	}

}

func TestGetValidCertificates(t *testing.T) {
	t.Parallel()
	// Generate fake certificates and add them to ssh-agent.
	sshagent := agent.NewKeyring()
	addedCerts := testCerts(t)
	addKeys(t, sshagent, addedCerts)

	tmp, err := ioutil.TempFile(t.TempDir(), "pam-sshca-unit-test")
	if err != nil {
		t.Fatal(err)
	}

	for _, cert := range addedCerts {
		ca := ssh.MarshalAuthorizedKey(cert.Certificate.SignatureKey)
		if _, err := tmp.Write(ca); err != nil {
			t.Fatal(err)
		}
	}

	a := &authenticator{
		config: &conf.Config{
			AllowCertificate: true,
			CAKeys:           []string{tmp.Name()},
		},
	}

	identities, err := getIdentitiesFromSSHAgent(sshagent)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != len(addedCerts) {
		t.Fatalf("Failed to get all the identities, expect %v, got %v.", len(addedCerts), len(identities))
	}
	for i := 0; i < len(identities); i++ {
		// The principal of each cert is from 0 to 9.
		certs := a.getValidCertificates(identities, strconv.Itoa(i))
		if len(certs) > 1 {
			t.Fatalf("Failed to eliminate invalid certificates with wrong principals: %v", certs)
		}
		if i != 4 && len(certs) != 0 {
			t.Fatalf("Failed to eliminate expired certificates: %v", certs)
		}
		if i == 4 && len(certs) != 1 {
			t.Fatalf("Failed to get valid certificates: %v", certs)
		}
	}
}
