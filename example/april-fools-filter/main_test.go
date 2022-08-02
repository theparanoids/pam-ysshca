// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/theparanoids/pam-ysshca/filter"
	"github.com/theparanoids/ysshra/keyid"
	"golang.org/x/crypto/ssh"
)

func testSSHCertificate(t *testing.T, keyID string) *ssh.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Error(err)
	}
	crt := &ssh.Certificate{
		KeyId:           keyID,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"prins"},
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
	return crt
}

func TestAprilFoolFilter_Filter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		generateData func(t *testing.T) ([]byte, []byte)
		filter       filter.Doer
		expectCert   bool
	}{
		{
			name: "happy path",
			generateData: func(t *testing.T) ([]byte, []byte) {
				kid := &keyid.KeyID{
					Principals: []string{"April", "May"},
					TransID:    "transID",
					ReqUser:    "reqUser",
					ReqIP:      "1.2.3.4",
					ReqHost:    "host",
					Version:    keyid.DefaultVersion,
					Usage:      keyid.AllUsage,
				}
				keyID, err := kid.Marshal()
				if err != nil {
					t.Fatal()
				}
				cert := testSSHCertificate(t, keyID)
				return ssh.MarshalAuthorizedKey(cert), ssh.MarshalAuthorizedKey(cert)
			},
			filter: NewAprilFoolFilter(func() time.Time {
				return time.Date(2000, time.Month(1), 1, 1, 1, 1, 0, time.UTC)
			}),
			expectCert: true,
		},
		{
			name: "no certificates for user April on April 1st",
			generateData: func(t *testing.T) ([]byte, []byte) {
				kid := &keyid.KeyID{
					Principals: []string{"April", "May"},
					TransID:    "transID",
					ReqUser:    "reqUser",
					ReqIP:      "1.2.3.4",
					ReqHost:    "host",
					Version:    keyid.DefaultVersion,
					Usage:      keyid.AllUsage,
				}
				keyID, err := kid.Marshal()
				if err != nil {
					t.Fatal()
				}
				cert := testSSHCertificate(t, keyID)
				return ssh.MarshalAuthorizedKey(cert), ssh.MarshalAuthorizedKey(cert)
			},
			filter: NewAprilFoolFilter(func() time.Time {
				return time.Date(2000, time.Month(4), 1, 12, 1, 1, 0, time.UTC)
			}),
		},
		{
			name: "invalid keyid cert should be rejected",
			generateData: func(t *testing.T) ([]byte, []byte) {
				cert := testSSHCertificate(t, "invlid-key-id")
				return ssh.MarshalAuthorizedKey(cert), ssh.MarshalAuthorizedKey(cert)
			},
			filter: NewAprilFoolFilter(func() time.Time {
				return time.Date(2000, time.Month(1), 1, 1, 1, 1, 0, time.UTC)
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, output := tt.generateData(t)
			result := tt.filter.Filter(input)
			if tt.expectCert && len(result) == 0 {
				t.Error("unable to get expected cert")
				return
			}
			if !tt.expectCert && len(result) != 0 {
				t.Error("should not receive cert, but has one")
				return
			}
			if tt.expectCert {
				if !bytes.Equal(output, result) {
					t.Errorf("cert data mismatch, got: \n%v\n, want: \n%v\n", string(result), string(output))
				}
			}
		})
	}
}
