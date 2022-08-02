// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package filter

import (
	"bytes"

	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
)

// SudoFilterRegular filters the certificates with SSHCA regular certificates.
type SudoFilterRegular struct{}

// Filter filters the certificates with SSHCA regular certificates.
func (*SudoFilterRegular) Filter(input []byte) []byte {
	keys, _, _ := key.GetPublicKeysFromBytes(input)
	buffer := new(bytes.Buffer)
	for _, key := range keys {
		cert, ok := key.(*ssh.Certificate)
		if !ok {
			// Reject non SSH certificates.
			continue
		}
		kID, err := keyid.Unmarshal(cert.KeyId)
		if err != nil {
			// Reject cert with invalid key id.
			continue
		}
		if kID.Usage == keyid.SSHOnlyUsage {
			// Reject cert with ssh permission only.
			continue
		}
		buffer.Write(ssh.MarshalAuthorizedKey(cert))
	}
	return buffer.Bytes()
}
