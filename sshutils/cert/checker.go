// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package cert

import (
	"crypto/sha256"
	"golang.org/x/crypto/ssh"
)

// CreateCertChecker creates the cert checker with public key provided.
func CreateCertChecker(CAKeys []ssh.PublicKey) *ssh.CertChecker {
	type hashcode [sha256.Size]byte

	var keyTable = make(map[hashcode]bool)
	for _, key := range CAKeys {
		if cert, ok := key.(*ssh.Certificate); ok {
			key = cert.Key
		}
		hash := sha256.Sum256(key.Marshal())
		keyTable[hash] = true
	}

	return &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			hash := sha256.Sum256(auth.Marshal())
			return keyTable[hash]
		},
	}
}
