// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"fmt"
	"log/syslog"

	"github.com/theparanoids/pam-ysshca/conf"
	"github.com/theparanoids/pam-ysshca/filter"
)

// AuthNFn is the interface to do authentication for the given principal.
// Currently, we don't set up multiple go PAM library into the same, because
// dynamically linking multiple cgo runtime into same process would cause the program
// crash. (A similar issue at go 1.7: https://github.com/golang/go/issues/18976).
// So we declare an interface here to inject secondary or fallback authN method (e.g. CryptoAuth)
// into PAM_SSHCA.
// TODO: Investigate the cgo runtime issue again and check if there's a workaround to
// integrate multiple cgo libraries into the same pam config.
type AuthNFn func(principal string, config conf.Config, sysLogger *syslog.Writer) error

var (
	r = newRegistry()
)

// registry is the struct to stored callback functions or options from external packages.
// External packages cannot invoke cgo functions, so we expose functions such as `AddFilter` and `SetNonSSHAgentAuthN`
// to enable other repos or packages to insert self-defined logic into PAM-SSHCA.
type registry struct {
	filters          map[string]filter.Doer
	nonSSHAgentAuthN AuthNFn
}

func newRegistry() *registry {
	return &registry{
		filters: map[string]filter.Doer{},
		nonSSHAgentAuthN: func(principal string, config conf.Config, sysLogger *syslog.Writer) error {
			return fmt.Errorf("no non-ssh-agent authentication method found")
		},
	}
}

// Filter returns the registered filter by the given name.
func Filter(ft string) (filter.Doer, error) {
	if filter, ok := r.filters[ft]; ok {
		return filter, nil
	}
	return nil, fmt.Errorf("invalid filter name %v", ft)
}

// AddFilter added a filter with its name into the registry.
func AddFilter(ft string, filter filter.Doer) {
	r.filters[ft] = filter
}

// NonSSHAgentAuthN returns the method of the fallback authentication when the ssh-agent connection fails.
func NonSSHAgentAuthN() AuthNFn {
	return r.nonSSHAgentAuthN
}

// SetNonSSHAgentAuthN sets the fallback authentication method when the ssh-agent connection fails.
func SetNonSSHAgentAuthN(fn AuthNFn) {
	r.nonSSHAgentAuthN = fn
}
