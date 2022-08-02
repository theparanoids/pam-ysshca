// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/theparanoids/ysshra/keyid"
	"github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
)

const blockedPrins = "april"

// aprilFoolFilter rejects certificates with the principals containing string "April".
type aprilFoolFilter struct {
	now func() time.Time
}

// NewAprilFoolFilter returns an aprilFoolFilter.
func NewAprilFoolFilter(now func() time.Time) *aprilFoolFilter {
	return &aprilFoolFilter{
		now: now,
	}
}

// Filter filters the certificates.
func (a *aprilFoolFilter) Filter(input []byte) []byte {
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
		_, month, date := a.now().Date()
		// Reject certs with principals containing blockedPrins on April 1st.
		if month == time.April && date == 1 {
			found := false
			for _, p := range kID.Principals {
				if strings.Contains(strings.ToLower(p), blockedPrins) {
					found = true
				}
			}
			if found {
				continue
			}
		}
		buffer.Write(ssh.MarshalAuthorizedKey(cert))
	}
	return buffer.Bytes()
}

func main() {
	filter := NewAprilFoolFilter(time.Now)
	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read from stdin, %v", err)
	}
	out := filter.Filter(in)
	os.Stdout.Write(out)
}
