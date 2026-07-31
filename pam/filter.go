// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"strings"

	"github.com/theparanoids/pam-ysshca/filter"
	"github.com/theparanoids/pam-ysshca/msg"
	"github.com/theparanoids/ysshra/sshutils/key"
	"golang.org/x/crypto/ssh"
)

// ResolveFilter resolves a filter path to a filter Doer. It supports embedded
// filters registered via AddFilter (referenced with the "embedded:" prefix) and
// external command filters referenced by their executable path.
func ResolveFilter(filterPath string) (filter.Doer, error) {
	if strings.HasPrefix(filterPath, filter.EmbeddedPrefix) {
		return Filter(strings.TrimPrefix(filterPath, filter.EmbeddedPrefix))
	}
	return filter.NewCommandFilter(filterPath)
}

func invokeFilter(keys []ssh.PublicKey, filterPath string) []ssh.PublicKey {
	flt, err := ResolveFilter(filterPath)
	if err != nil {
		msg.Printlf(msg.WARN, "failed to lookup filter %s: %v", filterPath, err)
		return []ssh.PublicKey{}
	}

	var input []byte
	for _, key := range keys {
		input = append(input, ssh.MarshalAuthorizedKey(key)...)
	}

	op := flt.Filter(input)
	rest, _, _ := key.GetPublicKeysFromBytes(op)
	return rest
}
