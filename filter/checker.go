// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package filter

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// CertChecker adapts a filter Doer into a certificate checker. It rejects any
// certificate that the underlying filter would filter out.
//
// It exists so that certificate authentication paths that do not run identities
// through the filters up front (e.g. the cryptoauth fallback used when ssh-agent
// is unavailable) can still enforce the same certificate restrictions as the
// ssh-agent path, such as sudo-filter-regular rejecting SSH-only certificates.
type CertChecker struct {
	// doer is the underlying filter applied to the certificate.
	doer Doer
}

// NewCertChecker returns a CertChecker backed by the given filter Doer.
func NewCertChecker(doer Doer) *CertChecker {
	return &CertChecker{doer: doer}
}

// CheckCert returns an error when the underlying filter rejects the certificate.
// The principal is unused here; principal validation is handled by the ssh
// CertChecker in the caller.
func (c *CertChecker) CheckCert(cert *ssh.Certificate, _ string) error {
	if c.doer == nil {
		return nil
	}
	// A filter accepts a certificate when it echoes it back in its output. An
	// empty result means the certificate was filtered out (rejected).
	output := c.doer.Filter(ssh.MarshalAuthorizedKey(cert))
	if len(bytes.TrimSpace(output)) == 0 {
		return fmt.Errorf("certificate rejected by filter")
	}
	return nil
}
