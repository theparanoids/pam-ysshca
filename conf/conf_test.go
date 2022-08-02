// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import (
	"reflect"
	"testing"
)

func TestConfig_AuthorizedPrincipals(t *testing.T) {
	tests := []struct {
		name                      string
		username                  string
		authorizedPrincipalPrefix []string
		authorizedPrincipalFiles  []string
		wantPrincipals            map[string]bool
		wantErr                   bool
	}{
		{
			name:                      "happy path",
			username:                  "user1",
			authorizedPrincipalPrefix: []string{"screwdriver"},
			authorizedPrincipalFiles:  []string{"./testdata/additional_authorized_principals_user1"},
			wantPrincipals:            map[string]bool{"screwdriveruser1": true, "user1": true, "user1:111": true, "user1:touch": true, "user2:222": true},
		},
		{
			name:                      "happy path",
			username:                  "user1",
			authorizedPrincipalPrefix: []string{"screwdriver"},
			authorizedPrincipalFiles:  []string{"invalid file path"},
			wantPrincipals:            map[string]bool{"screwdriveruser1": true, "user1": true},
			wantErr:                   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{
				authorizedPrincipalPrefix: tt.authorizedPrincipalPrefix,
				authorizedPrincipalFiles:  tt.authorizedPrincipalFiles,
			}
			gotPrincipals, err := c.AuthorizedPrincipals(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthorizedPrincipals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPrincipals, tt.wantPrincipals) {
				t.Errorf("AuthorizedPrincipals() gotPrincipals = %v, want %v", gotPrincipals, tt.wantPrincipals)
			}
		})
	}
}
