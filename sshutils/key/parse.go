// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package key

import (
	"github.com/theparanoids/pam-ysshca/sshutils/key"
	"golang.org/x/crypto/ssh"
)

// GetPublicKeysFromFiles get all the public keys from the given list of filepath.
func GetPublicKeysFromFiles(userCAKeysFiles []string) []ssh.PublicKey {
	var caKeys []ssh.PublicKey
	for _, userCAKeyFile := range userCAKeysFiles {
		key, _, err := key.GetPublicKeysFromFile(userCAKeyFile)
		if err != nil {
			continue
		}
		caKeys = append(caKeys, key...)
	}
	return caKeys
}
