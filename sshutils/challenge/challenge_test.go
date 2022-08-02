// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package challenge

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func testSSHCertificate(t *testing.T, prins ...string) (*ssh.Certificate, ssh.PublicKey, *rsa.PrivateKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Error(err)
	}
	crt := &ssh.Certificate{
		KeyId:           "keyID",
		CertType:        ssh.UserCert,
		ValidPrincipals: prins,
		Key:             pub,
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Unix()) + 1000,
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Error(err)
	}
	if err := crt.SignCert(rand.Reader, signer); err != nil {
		t.Error(err)
	}
	return crt, pub, priv
}

func TestChallenge(t *testing.T) {
	t.Parallel()

	cert, _, _ := testSSHCertificate(t, "example_user")

	ch, err := NewChallenge(cert)
	if err != nil {
		t.Fatalf("unexpected error, err: %v", err)
	}
	chReqData, err := ch.ChallengeRequest()
	if err != nil {
		t.Fatalf("unexpected error, err: %v", err)
	}
	cd := &Data{}
	// verify if data is marshalled correctly
	if err := cd.Unmarshal(chReqData); err != nil {
		t.Fatalf("unexpected error, err: %v", err)
	}
	if !reflect.DeepEqual(cd.Data, ch.data.Data) {
		t.Fatalf("data string doesn't match, got %v, want %v", cd.Data, ch.data.Data)
	}

	ch2, _ := NewChallenge(cert)
	if err != nil {
		t.Fatalf("unexpected error, err: %v", err)
	}
	if reflect.DeepEqual(ch.data, ch2.data) {
		t.Fatalf("got same challenge, expected different challenge")
	}
}

func TestVerifyChallenge(t *testing.T) {
	t.Parallel()

	cert, _, priv := testSSHCertificate(t, "test_user")
	ch, err := NewChallenge(cert)
	if err != nil {
		t.Fatal(err)
	}

	ag := agent.NewKeyring()
	addedKey := agent.AddedKey{
		PrivateKey:   priv,
		Certificate:  cert,
		LifetimeSecs: uint32(time.Hour / time.Second),
		Comment:      "comment",
	}
	if err := ag.Add(addedKey); err != nil {
		t.Fatal(err)
	}
	sig, err := ag.Sign(cert, ch.data.Data)
	if err != nil {
		t.Error(err)
	}
	cd := *ch.data
	cd.Signature = *sig
	resp, err := cd.Marshal()
	if err != nil {
		t.Error(err)
	}

	table := map[string]struct {
		ch        *Challenge
		resp      string
		expectErr bool
	}{
		"valid": {
			ch:   ch,
			resp: string(resp),
		},
		"empty resp": {
			ch:        ch,
			resp:      "",
			expectErr: true,
		},
		"invalid resp": {
			ch:        ch,
			resp:      "invalid",
			expectErr: true,
		},
	}
	for name, tt := range table {
		t.Run(name, func(t *testing.T) {
			err := tt.ch.VerifyResponse(tt.resp)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error for invalid test %v, got nil", name)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for test %v, err: %v", name, err)
				}
			}
		})
	}
}
