// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package conf

import (
	"reflect"
	"regexp"
	"testing"
)

const validConfig = `
Debug off
Filter /etc/filter1
Filter embedded:filter2
Filter test/filter3
AllowStaticKeys yes
AuthorizedKeysFile /etc/ssh/sample1.pub
AuthorizedKeysFile /etc/ssh/sample2.pub
AuthorizedKeysFile /etc/ssh/%u.pub
AllowCertificate yes
SupportedCriticalOption critical-option 
TrustedUserCAKeys /etc/ssh/sshuca
AuthorizedPrincipalsFile /etc/testAPfile
AuthorizedPrincipalPrefix screwdriver:
Prompt touchPolicy=(2|3) Touch YubiKey:
`

func TestParser_extendFilePath(t *testing.T) {
	tests := []struct {
		name      string
		userName  string
		userHome  string
		inputPath string
		want      string
	}{
		{
			name:      "happy path",
			userName:  "example_user",
			inputPath: "/etc/ssh/additional_authorized_principals/%u",
			want:      "/etc/ssh/additional_authorized_principals/example_user",
		},
		{
			name:      "embedded filter",
			userName:  "example_user",
			inputPath: "embedded:AbcFilter",
			want:      "embedded:AbcFilter",
		},
		{
			name:      "user self defined filter at home dir",
			userName:  "example_user",
			userHome:  "/home/example_user",
			inputPath: "test/example_filter",
			want:      "/home/example_user/test/example_filter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.userName, tt.userHome)
			if got := p.extendFilePath(tt.inputPath); got != tt.want {
				t.Errorf("extendFilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_ParseConfigFile(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		userHome string
		config   []byte
		want     Config
	}{
		{
			name:     "happy path",
			userName: "example_user",
			userHome: "/home/example_user",
			config:   []byte(validConfig),
			want: Config{
				Filters: []string{
					"/etc/filter1",
					"embedded:filter2",
					"/home/example_user/test/filter3",
				},
				AllowStaticKeys: true,
				StaticKeys: []string{
					"/etc/ssh/sample1.pub",
					"/etc/ssh/sample2.pub",
					"/etc/ssh/example_user.pub",
				},
				AllowCertificate: true,
				SupportedCriticalOptions: []string{
					"critical-option",
				},
				CAKeys: []string{
					"/etc/ssh/sshuca",
				},
				authorizedPrincipalPrefix: []string{
					"screwdriver:",
				},
				authorizedPrincipalFiles: []string{
					"/etc/testAPfile",
				},
				Prompters: []Prompter{
					{
						KeyIDProperty: "touchPolicy",
						RE:            regexp.MustCompile("(2|3)"),
						Message:       "Touch YubiKey:",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Parser{
				userName: tt.userName,
				userHome: tt.userHome,
			}
			if got := p.parse(tt.config); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseConfigFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
