// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/theparanoids/pam-ysshca/filter"
	"golang.org/x/crypto/ssh"
	"reflect"
	"testing"
)

type filterIn struct{}

func (*filterIn) Filter(b []byte) []byte { return b }

type filterOut struct{}

func (*filterOut) Filter(b []byte) []byte { return nil }

func testPubKeys(t *testing.T) []ssh.PublicKey {
	var pubKeys []ssh.PublicKey
	for i := 0; i < 10; i++ {
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			continue
		}
		pub, err := ssh.NewPublicKey(&private.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pubKeys = append(pubKeys, pub)
	}
	return pubKeys
}

func Test_invokeFilter(t *testing.T) {
	pubKeys := testPubKeys(t)
	tests := []struct {
		name        string
		setupFilter func(t *testing.T) string
		keys        []ssh.PublicKey
		want        []ssh.PublicKey
	}{
		{
			name: "all keys filter in",
			setupFilter: func(t *testing.T) string {

				// Add Filter.
				path := "filter1"
				AddFilter(path, &filterIn{})
				return path
			},
			keys: pubKeys,
			want: pubKeys,
		},
		{
			name: "all keys filter out",
			setupFilter: func(t *testing.T) string {
				path := "filter2"
				AddFilter(path, &filterOut{})
				return path
			},
			keys: pubKeys,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fpath := tt.setupFilter(t)
			if got := invokeFilter(tt.keys, filter.EmbeddedPrefix+fpath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("invokeFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}
